#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* mazen code start 2*/
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
/* amzen code end 2*/


static void syscall_handler (struct intr_frame *);

/* mazen code start 2*/
// create a lock for file system
struct lock filesys_lock;

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void process_close_file (int fd);

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);


int process_add_file (struct file *f);
struct file* process_get_file (int fd);
int user_to_kernel_ptr(const void *vaddr);
void get_arg (struct intr_frame *f, int *arg, int n);
void check_valid_ptr (const void *vaddr);
void check_valid_buffer (void* buffer, unsigned size);
/*mazen code end 2*/

void
syscall_init (void) 
{
  /*mazen code start*/
  lock_init(&filesys_lock);
  /*mazen code end*/

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* mazen code start 2*/
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	// syscall functions args maximum 3 args
  int arg[3];

  check_valid_ptr((const void*) f->esp);

  switch (* (int *) f->esp) // get the saved stack pointer of the interrupted thread
    {
    case SYS_HALT:
      {
	halt(); 
	break;
      }
    case SYS_EXIT:
      {
	get_arg(f, &arg[0], 1);
	exit(arg[0]);
	break;
      }
    case SYS_EXEC:
      {
	get_arg(f, &arg[0], 1);
	// get kernel virtual address 
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = exec((const char *) arg[0]); // save return value in the 32bit accumulator EAX
	break;
      }
    case SYS_WAIT:
      {
	get_arg(f, &arg[0], 1);
	f->eax = wait(arg[0]);
	break;
      }
    case SYS_CREATE:
      {
	get_arg(f, &arg[0], 2);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	break;
      }
    case SYS_REMOVE:
      {
	get_arg(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = remove((const char *) arg[0]);
	break;
      }
    case SYS_OPEN:
      {
	get_arg(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = open((const char *) arg[0]);
	break; 		
      }
    case SYS_FILESIZE:
      {
	get_arg(f, &arg[0], 1);
	f->eax = filesize(arg[0]);
	break;
      }
    case SYS_READ:
      {
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	break;
      }
    case SYS_WRITE:
      { 
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = write(arg[0], (const void *) arg[1],
		       (unsigned) arg[2]);
	break;
      }
    case SYS_SEEK:
      {
	get_arg(f, &arg[0], 2);
	seek(arg[0], (unsigned) arg[1]);
	break;
      } 
    case SYS_TELL:
      { 
	get_arg(f, &arg[0], 1);
	f->eax = (int )tell(arg[0]);
	break;
      }
    case SYS_CLOSE:
      { 
	get_arg(f, &arg[0], 1);
	close(arg[0]);
	break;
      }
    }
}

/* mazen code end 2*/


/* maze code start*/

// try to open the file if file exist returns its discriptor fd
int open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int fd = process_add_file(f);
  lock_release(&filesys_lock);
  return fd;
}

// add file in thread's list of files with its fd(file discriptor)
int process_add_file (struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &pf->elem);
  return pf->fd;
}

// get specific file from thread's list of files with its fd(file discriptor)
struct file* process_get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
        {
          struct process_file *pf = list_entry (e, struct process_file, elem);
          if (fd == pf->fd)
	    {
	      return pf->file;
	    }
        }
  return NULL;
}

//Returns the size, in bytes, of the file open as fd
int filesize (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
}

// read number of bytes (size) from a file or keyboard and return number of theze bytes
int read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)// fd 0 then reading from keyboard
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
	{
	  local_buffer[i] = input_getc();
	}
      return size;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_read(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

// writes bytes in buffer into a file or console(fd 1), returns number of bytes written
int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)// fd 1
    {
      // there was something about break up 
      //larger buffers but i don't know how 
      putbuf(buffer, size);
      return size;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_write(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

//Changes the next byte to be read or written in open file fd to position
void seek (int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return;
    }
  file_seek(f, position);
  lock_release(&filesys_lock);
}

//Returns the position of the next byte to be read or written in open file fd, expressed in
//bytes from the beginning of the file. 
unsigned tell (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  off_t offset = file_tell(f);
  lock_release(&filesys_lock);
  return offset;
}

// closes specific file or all files in current thread
void close (int fd)
{
  lock_acquire(&filesys_lock);
  process_close_file(fd);
  lock_release(&filesys_lock);
}

void process_close_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->file_list);

  while (e != list_end (&t->file_list))
    {
      next = list_next(e);
      struct process_file *pf = list_entry (e, struct process_file, elem);
      if (fd == pf->fd || fd == CLOSE_ALL)
	{
	  file_close(pf->file);
	  list_remove(&pf->elem);
	  free(pf);
	  if (fd != CLOSE_ALL)
	    {
	      return;
	    }
	}
      e = next;
    }
}

// get all args used by any of the syscall 
void get_arg (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_ptr((const void *) ptr);
      arg[i] = *ptr;
    }
}

// checks that the given address is in user space, and is not null.
// We must exit the program and free its resources shouldany of these conditions be violated
void check_valid_ptr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr) || vaddr < (void *) 0x08048000 || vaddr == NULL)
    {
      exit(ERROR);
    }
}

// get kernel virtual address
int user_to_kernel_ptr(const void *vaddr)
{
  check_valid_ptr(vaddr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
    {
      exit(ERROR);
    }
  return (int) ptr;
}

//Ensures that each memory address in a given buffer is in valid user space.
void check_valid_buffer (void* buffer, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      check_valid_ptr((const void*) local_buffer);
      local_buffer++;
    }
}

/*mazen code end*/