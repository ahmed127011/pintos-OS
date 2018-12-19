#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */

/*mazen code start 2*/
#define CLOSE_ALL -1
#define ERROR -1

void process_close_file (int fd);
/*mazen code end 2*/