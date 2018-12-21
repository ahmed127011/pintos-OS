#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "kernel/console.h"
#include "list.h"
typedef int pid_t;
static void syscall_handler (struct intr_frame *);
static bool valid_user_prog_ptr(const void* ptr);
static void get_params(int* ptr, int* params[], int count);
static void halt(void);
static int wait_for_child(pid_t pid);
static void exit (int status);
static tid_t exec (const char *cmd_line);


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
int process_add_file (struct file *f);
struct file* process_get_file (int fd);


int create_file(const char *file, unsigned initial_size);
int remove_file(const char *file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
   int* stack_ptr = (int *)f->esp;

 /* Checks whether valid pointer reference. */
 if(!valid_user_prog_ptr(stack_ptr))
    exit(-1);

 int* params[4];

switch(*stack_ptr)
{    
    case SYS_HALT:                                /* System Call HALT. */
       halt();
       break;               
    case SYS_EXIT:                                /* System Call EXIT. */
      get_params(stack_ptr, params, 1);
      exit (*params[0]);
      break;                  
    case SYS_EXEC:                                /* System Call EXEC. */
      get_params(stack_ptr, params, 1);
      f->eax = exec ((char *)*params[0]);
      break;                   
    case SYS_WAIT:                                /* System Call WAIT. */                 
      get_params(stack_ptr, params, 1);
      f->eax = wait_for_child (*params[0]);
      break;                                  
    case SYS_CREATE:                              
      get_params(stack_ptr, params, 2);
      f->eax = create_file((const char*)*params[0], *((unsigned*)params[1]));    
      break;                
    case SYS_REMOVE:                              
      get_params(stack_ptr, params, 1);
      f->eax = remove_file((const char*)*params[0]);
      break;              
    case SYS_OPEN:                                
      get_params(stack_ptr, params, 1);
      f->eax = open((const char *)*params[0]);
      break;                 
    case SYS_FILESIZE:                            
      get_params(stack_ptr, params, 1);
      f->eax = filesize(*params[0]);
      break;             
    case SYS_READ:                                
      get_params(stack_ptr, params, 3);
      f->eax = read(*params[0], (void *)(*params[1]), *((unsigned*)params[2]));
      break;                   
    case SYS_WRITE:                               
      get_params(stack_ptr, params, 3);
      f->eax = write(*params[0], (const void *)(*params[1]), *((unsigned*)params[2]));
      break;                  
    case SYS_SEEK:                                
      get_params(stack_ptr, params, 2);
      seek(*params[0], *((unsigned*)params[1]));   
      break;                  
    case SYS_TELL:                                
      get_params(stack_ptr, params, 1);
      f->eax = tell(*params[0]);
      break;                 
    case SYS_CLOSE:                               
      get_params(stack_ptr, params, 1);
      close (*params[0]);
      break;
    default:
        exit(-1);
        break;   
   }
}


static void
get_params(int* ptr, int* params[], int count)
{
  int i;
  bool terminate = false;
  for(i = 1; i <= count; i++){

       int* curr_ptr = ptr + i;
       if(!valid_user_prog_ptr((const void*)curr_ptr)){

          terminate = true;
          break;

       }
     params[i - 1] = curr_ptr;  
     
  }
  if(terminate)
     exit(-1);
}

static bool
valid_user_prog_ptr(const void* ptr)
{
  if(ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
      return true;

  return false;
}

static void
halt(void) {  
  shutdown_power_off();
}


static void
exit (int status)
{
  struct thread* current_thread = thread_current();
  
  current_thread->exit_state = status;
  if(current_thread->parent_thread != NULL) {

    struct list_elem *e; 
    for (e = list_begin (& current_thread->parent_thread->child_process); 
                e != list_end (& current_thread->parent_thread->child_process);      
            e = list_next (e))
          {
                  struct child_thread* child = list_entry(e, struct child_thread, child_elem);
              
                  if(child->child_tid == current_thread->tid){
                    child->exit_state = status;
                          break;
                        }
                }
  }
  thread_exit();
}

static tid_t
exec (const char *cmd_line) {

 /* Checks whether valid string. */
 if(!valid_user_prog_ptr((void*) cmd_line))
     exit(-1);

 struct thread* current_thread = thread_current();
 current_thread->is_child_loaded_successfully = false;

 tid_t child_pid = process_execute(cmd_line);

 sema_down(&current_thread->loaded_successfully);

 if(!current_thread->is_child_loaded_successfully)
     return -1;


 return child_pid;
}

wait_for_child(pid_t pid) {
   return process_wait(pid);
}

int
create_file(const char *file, unsigned initial_size)
{
    if(!(valid_user_prog_ptr((void*) file)))
  exit(-1);

   file_sys_lock_acquire();
    bool success = filesys_create(file,initial_size);
    file_sys_lock_release();
    return success;
 
 
}
int
remove_file(const char *file)
{
    file_sys_lock_acquire();
    bool success = filesys_remove (file);
    file_sys_lock_release();
    return success;
 
 
}
/* maze code start*/

// try to open the file if file exist returns its discriptor fd
int open (const char *file)
{
if(!(valid_user_prog_ptr((void*) file)))
  exit(-1);
  file_sys_lock_acquire();
  struct file *f = filesys_open(file);
  if (!f)
    {
      file_sys_lock_release();
      return ERROR;
    }
  int fd = process_add_file(f);
  file_sys_lock_release();
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
  file_sys_lock_acquire();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      file_sys_lock_release();
      return ERROR;
    }
  int size = file_length(f);
  file_sys_lock_release();
  return size;
}

// read number of bytes (size) from a file or keyboard and return number of theze bytes
int read (int fd, void *buffer, unsigned size)
{
if(!(valid_user_prog_ptr((void*) buffer)))
  exit(-1);
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
  file_sys_lock_acquire();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_read(f, buffer, size);
  file_sys_lock_release();
  return bytes;
}

// writes bytes in buffer into a file or console(fd 1), returns number of bytes written
int write (int fd, const void *buffer, unsigned size)
{
if(!(valid_user_prog_ptr((void*) buffer)))
  exit(-1);
  if (fd == STDOUT_FILENO)// fd 1
    {
      // there was something about break up 
      //larger buffers but i don't know how 
      putbuf(buffer, size);
      return size;
    }
  file_sys_lock_acquire();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      file_sys_lock_release();
      return ERROR;
    }
  int bytes = file_write(f, buffer, size);
  file_sys_lock_release();
  return bytes;
}

//Changes the next byte to be read or written in open file fd to position
void seek (int fd, unsigned position)
{
  file_sys_lock_acquire();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      file_sys_lock_release();
      return;
    }
  file_seek(f, position);
  file_sys_lock_release();
}

//Returns the position of the next byte to be read or written in open file fd, expressed in
//bytes from the beginning of the file. 
unsigned tell (int fd)
{
  file_sys_lock_acquire();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      file_sys_lock_release();
      return ERROR;
    }
  off_t offset = file_tell(f);
  file_sys_lock_release();
  return offset;
}

// closes specific file or all files in current thread
void close (int fd)
{
  file_sys_lock_acquire();
  process_close_file(fd);
  file_sys_lock_release();
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



