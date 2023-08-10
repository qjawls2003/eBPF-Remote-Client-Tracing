struct data_t {
   __u32 pid;
   __u32 uid;
   char command[16];
   int ret;
   struct sockaddr_in addr;
};
