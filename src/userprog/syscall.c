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
  /*  case SYS_CREATE:                              
      get_params(stack_ptr, params, 2);
      f->eax = create_file((const char*)*params[0], *((unsigned*)params[1]));    
      break;                
    case SYS_REMOVE:                              
      get_params(stack_ptr, params, 1);
      f->eax = remove_file((const char*)*params[0]);
      break;                
    case SYS_OPEN:                                
      get_params(stack_ptr, params, 1);
      f->eax = open_file((const char *)*params[0]);
      break;                 
    case SYS_FILESIZE:                            
      get_params(stack_ptr, params, 1);
      f->eax = filesize(*params[0]);
      break;             
    case SYS_READ:                                
      get_params(stack_ptr, params, 3);
      f->eax = read_file(*params[0], (void *)(*params[1]), *((unsigned*)params[2]));
      break;                   
    case SYS_WRITE:                               
      get_params(stack_ptr, params, 3);
      f->eax = write_file(*params[0], (const void *)(*params[1]), *((unsigned*)params[2]));
      break;                  
    case SYS_SEEK:                                
      get_params(stack_ptr, params, 2);
      seek_file(*params[0], *((unsigned*)params[1]));   
      break;                  
    case SYS_TELL:                                
      get_params(stack_ptr, params, 1);
      f->eax = tell_file (*params[0]);
      break;                 
    case SYS_CLOSE:                               
      get_params(stack_ptr, params, 1);
      close_file (*params[0]);
      break;*/
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
