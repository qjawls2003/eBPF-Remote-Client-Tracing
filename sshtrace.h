struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[16];
   struct sockaddr *client_ip;
};

struct msg_t {
   char message[12];
};
