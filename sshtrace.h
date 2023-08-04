struct sockaddr_t {
	unsigned short sa_family;
	char sa_data[14];
};

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[16];
   char sa_data[14];
   struct sockaddr_t sockaddr;
};

struct msg_t {
   char message[12];
};
