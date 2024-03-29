#include "userprog/process.h"
#include "threads/malloc.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif
#include <hash.h>

#define CHAR_SIZE 4

/* Captures pre-processed arguments from process_execute() to pass to
 start_process() and load(). */
typedef struct
{
  char** argv; /* command-line arguments */
  char* filename; /* name of the executable */
  char* tmp_page_addr; /* base address of page allocated for command line */
  int argc; /* argument count */
} process_info;

static thread_func start_process NO_RETURN;
static bool load (process_info *pinfo, void (**eip) (void),
      void **esp);

/* Starts a new thread running a user program loaded from
 FILENAME.  The new thread may be scheduled (and may even exit)
 before process_execute() returns.  Returns the new process's
 thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
   Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  size_t filename_length = strlcpy (fn_copy, file_name, PGSIZE);

  char *token, *save_ptr;

  int page_offset = filename_length + 1;

  /* Store arg_page in page allocated earlier. avoids malloc. */
  char **arg_page = (char**) &fn_copy[page_offset];

  int page_index = 0;

  /* Break up command line into words and store in arg_page. */
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL; token =
      strtok_r (NULL, " ", &save_ptr))
    {
      /* Check if it is valid memory before writing. */
      if ((uint32_t) &arg_page[page_index + 1]
          - (uint32_t) fn_copy> (uint32_t) PGSIZE)
        {
          palloc_free_page (fn_copy);
          return TID_ERROR;
        }

      arg_page[page_index++] = token;
    }
  arg_page[page_index] = NULL;

  process_info *pinfo = malloc (sizeof(process_info));
  if (pinfo == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
  pinfo->filename = arg_page[0];
  pinfo->argv = arg_page;
  pinfo->tmp_page_addr = fn_copy;
  pinfo->argc = page_index;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (pinfo->filename, PRI_DEFAULT, start_process, pinfo);

  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      printf ("thread_create failed\n");
    }
  return tid;
}

/* A thread function that loads a user process and starts it
 running. */
static void
start_process (void *args)
{
  process_info *pinfo = (process_info *) args;

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (pinfo, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (pinfo->tmp_page_addr);
  free (pinfo);

  if (!success)
    {
      thread_current ()->process->exit_status = -1;
      sema_up (&thread_current ()->process->exec_child);
      exit (-1);
    }
  else
    {
      sema_up (&thread_current ()->process->exec_child);
    }

  /* Start the user process by simulating a return from an
   interrupt, implemented by intr_exit (in
   threads/intr-stubs.S).  Because intr_exit takes all of its
   arguments on the stack in the form of a `struct intr_frame',
   we just point the stack pointer (%esp) to our stack frame
   and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ()
  ;
}

/* Waits for thread TID to die and returns its exit status.  If
 it was terminated by the kernel (i.e. killed due to an
 exception), returns -1.  If TID is invalid or if it was not a
 child of the calling process, or if process_wait() has already
 been successfully called for the given TID, returns -1
 immediately, without waiting. */
int
process_wait (tid_t child_tid)
{

  struct thread *cur = thread_current ();

  /* Get lock because the child_list is also edited by children. */
  lock_acquire (&cur->child_hash_lock);

  struct process_data* cp = process_from_tid (child_tid, &cur->child_hash);
  if (cp == NULL)
    {
      lock_release (&cur->child_hash_lock);
      return -1;
    }

  while (!cp->finished)
    {
      cond_wait (&cp->cond_on_child, &cur->child_hash_lock);
    }

  hash_delete (&cur->child_hash, &cp->elem);
  int return_value = cp->exit_status;
  free (cp);
  lock_release (&cur->child_hash_lock);
  return return_value;
}

/* Frees the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
   to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
 thread.
 This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
   interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
 from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
 There are e_phnum of these, starting at file offset e_phoff
 (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool
setup_stack (void **esp);
static bool
validate_segment (const struct Elf32_Phdr *, struct file *);
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
    uint32_t zero_bytes,
    bool writable);
static void
stack_push (void** esp, char* c);
static bool
populate_stack (process_info *pinfo, void** esp);

/* Pushes word to string on stack. */
static void
stack_push (void** esp, char* c)
{
  *esp -= CHAR_SIZE;
  char** sp = (char**) *esp;
  *sp = c;
}

/* Populates stack for executable with arguments for execution. */
static bool
populate_stack (process_info *pinfo, void** esp)
{
  char **argv = pinfo->argv;
  int i;
  for (i = pinfo->argc - 1; i >= 0; i--)
    {
      int length = strlen (argv[i]) + 1; /* Include null-terminator. */
      *esp -= length;
      /* no need to check memory, because a similar check was done in
       * process_execute */
      strlcpy (*esp, argv[i], length);
      argv[i] = *esp;
    }

  /* For best performance, round stack pointer to multiple of 4 before first
   * push. */
  uint32_t sp = (uint32_t) *esp;
  *esp = (void*) (sp - (sp % 4));

  /* check if we have enough space in the page for the rest of the arguments */
  uint32_t min_esp_addr = (uint32_t) PHYS_BASE - PGSIZE * CHAR_SIZE;
  uint32_t final_esp_addr = (uint32_t) *esp - (pinfo->argc + 3) * CHAR_SIZE;
  if (min_esp_addr > final_esp_addr)
    {
      return false;
    }

  for (i = pinfo->argc; i >= 0; i--)
    {
      stack_push (esp, argv[i]);
    }

  stack_push (esp, (char*) *esp);
  stack_push (esp, (char*) pinfo->argc);
  stack_push (esp, (char*) NULL);
  return true;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
 Stores the executable's entry point into *EIP
 and its initial stack pointer into *ESP.
 Returns true if successful, false otherwise. */
bool
load (process_info *pinfo, void
(**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *file_name = pinfo->argv[0];
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;

  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name, NULL);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
  file_deny_write (file);
  thread_current ()->executable = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
      || ehdr.e_machine != 3 || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment (&phdr, file))
          {
            bool writable = (phdr.p_flags & PF_W) != 0;
            uint32_t file_page = phdr.p_offset & ~PGMASK;
            uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
            uint32_t page_offset = phdr.p_vaddr & PGMASK;
            uint32_t read_bytes, zero_bytes;
            if (phdr.p_filesz > 0)
              {
                /* Normal segment.
                 Read initial part from disk and zero the rest. */
                read_bytes = page_offset + phdr.p_filesz;
                zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                    - read_bytes);
              }
            else
              {
                /* Entirely zero.
                 Don't read anything from disk. */
                read_bytes = 0;
                zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
              }
            if (!load_segment (file, file_page, (void *) mem_page, read_bytes,
                zero_bytes, writable))
              goto done;
          }
        else
          goto done;
        break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp) || !populate_stack (pinfo, esp))
    {
      goto done;
    }

  /* Start address. */
  *eip = (void
  (*) (void)) ehdr.e_entry;

  success = true;

  done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* Load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
 FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    {
      return false;
    }
  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
   user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
   address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
   Not only is it a bad idea to map page 0, but if we allowed
   it then user code that passed a null pointer to system calls
   could quite likely panic the kernel by way of null pointer
   assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 memory are initialized, as follows:

 - READ_BYTES bytes at UPAGE must be read from FILE
 starting at offset OFS.

 - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

 The pages initialized by this function must be writable by the
 user process if WRITABLE is true, read-only otherwise.

 Return true if successful, false if a memory allocation error
 or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
    uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs (upage) == 0);
  ASSERT(ofs % PGSIZE == 0);


#ifdef VM
  struct backed_file *segment = malloc (sizeof(struct backed_file));
  segment->file = file_reopen (file);
  segment->id = thread_current ()->next_backed_file_id;
  thread_current ()->next_backed_file_id++;
  /* The executable is not actually a mapped file. */
  segment->is_segment = true;
  segment->num_bytes = read_bytes + zero_bytes + ofs;
  hash_insert (&thread_current ()->backed_file_hash_table, &segment->elem);
#else
  file_seek (file, ofs);
#endif

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
      /* Do lazy loading, so we don't actually get the page from memory. We
       only create the supplemental page table entry. We use the mmaped
       file struct for convenience. */
      struct page_data *data = page_create_data (upage);
      page_set_mmaped_file (data, segment, ofs, page_read_bytes);
      ofs += PGSIZE;
      data->is_writable = writable;

#else
      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page(PAL_USER);

      if (kpage == NULL)
        {
          return false;
        }

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
 user virtual memory. */
static bool
setup_stack (void **esp)
{
  bool success = false;

#ifdef VM
  struct frame* frame = frame_get_new (PHYS_BASE - PGSIZE, true, NULL, false);
  success = frame != NULL;

#else
  uint8_t * kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    }

  if (!success)
    {
      palloc_free_page (kpage);
    }
#endif

  if (success)
    *esp = PHYS_BASE;

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 virtual address KPAGE to the page table.
 If WRITABLE is true, the user process may modify the page;
 otherwise, it is read-only.
 UPAGE must not already be mapped.
 KPAGE should probably be a page obtained from the user pool
 with palloc_get_page().
 Returns true on success, false if UPAGE is already mapped or
 if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
   address, then map our page there. */
  bool success = pagedir_get_page (t->pagedir, upage) == NULL
      && pagedir_set_page (t->pagedir, upage, kpage, writable);
  if (!success)
    {
      return false;
    }
#ifdef VM
  page_create_data (upage);
#endif
  return success;
}
