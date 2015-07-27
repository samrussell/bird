//  Hello World server

#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

int main (int argc, char** argv)
{
    // unix socket data
    int s, s2, t, len, childPID;
    struct sockaddr_un local, remote;
    char str[100];
    char* unixsocket;
    int pipefds[2];
    //  Socket to talk to clients
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5556");
    assert (rc == 0);

    if (argc < 2){
        printf("Usage: zmqlisten [socket]\n");
        exit(-1);
    }

    // connect unix socket

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    unixsocket = argv[1];


    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, unixsocket);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr *)&local, len) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(s, 5) == -1) {
        perror("listen");
        exit(1);
    }

        for(;;) {
          int done, n, zmqwantreply;
          char* inbuf = NULL;
          inbuf = calloc(1,12000);
          printf("Waiting for a connection...\n");
          t = sizeof(remote);
          if ((s2 = accept(s, (struct sockaddr *)&remote, &t)) == -1) {
              perror("accept");
              exit(1);
          }

          printf("Connected.\n");
          // make non-blocking
          fcntl(s2, F_SETFL, O_NONBLOCK);

          done = 0;
          zmqwantreply = 0;
          do {
              char buffer [10];
              printf("Checking unix socket\n");
              errno = 0;
              while(errno == 0){
                  n = recv(s2, inbuf, 12000, 0);
                  if (n <= 0) {
                      if (errno != EAGAIN && errno != EWOULDBLOCK){
                          if (n < 0) perror("recv");
                          done = 1;
                      }
                  }
                  else { 
                      printf("Received %s\n", inbuf);
              /*        if (send(s2, str, n, 0) < 0) {
                          perror("send");
                          done = 1; 
                      }*/
                      // send to zeromq if is dump and zmq wants reply
                      // this will cut off the end so need to recode
                      if(strlen(inbuf) > 10 && !strncmp(inbuf, "<SDN_DUMP>", 10) && zmqwantreply){
                          // do reply
                          printf("Got reply, sending over zeromq\n");
                          zmqwantreply = 0;
                          zmq_send (responder, inbuf, n, 0);
                      }
                  }
              }
              if (errno == EAGAIN || errno == EWOULDBLOCK){
                  errno = 0;
              }
              printf("Checking zmq socket\n");
              // don't do anything here until we get the reply for zeromq
              while(errno == 0 && !zmqwantreply){
                  char zmqreq[] = "gary";
                  zmq_pollitem_t items [] = {
                      { responder,   0, ZMQ_POLLIN, 0 }
                  };
                  printf("calling zmq_recv\n");
                  zmq_poll (items, 1, 0);
                  if(items [0].revents & ZMQ_POLLIN){
                      zmq_recv (responder, buffer, 10, 0); //, ZMQ_DONTWAIT);
                  //if(errno != EAGAIN){
                      printf ("Received Hello\n");
                      zmqwantreply = 1; // maybe increment?
                      if (send(s2, zmqreq, strlen(zmqreq)+1, 0) < 0) {
                          perror("send");
                          done = 1; 
                      }
                      // set errno = 0 as zmq_recv does bad things to it
                      errno = 0;
                  }
                  // fake errno for now
                  errno = EAGAIN;
              }
              if (errno != 0 && errno != EAGAIN){
                  //printf("Error: %d\n", errno);
                  perror("nonblockcheck");
                  done = 1;
              }
              if (errno == EAGAIN){
                  errno = 0;
              }
              sleep(1);
          } while (!done);

            close(s2);
            if(inbuf){
                free(inbuf);
                inbuf = NULL;
            }
        }
    return 0;
}
