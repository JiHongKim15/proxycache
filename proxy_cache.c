//////////////////////////////////////////////////////////////////////////
// File Name   : proxy_cache.c           			        //
// Date      : 2018/06/08               				//
// Os      : Ubuntu 16.04 LTS 64bits    			        //
// Author   : Kim Ji Hong            					//
// Student ID   : 2015722018              				//
// ---------------------------------------------------------------------//
// Title : System Programming Assignment #3-2 (proxy server)    	//
// Description : Loging using threads					//
//////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <pthread.h>


#define BUFFSIZE   50000 //Buffer size
#define PORTNO      38055 //port number

int pnum = 0;
FILE *flog;
time_t now;
time_t start, end;
int socket_fd, client_fd;
pthread_t tid;
struct tm *ltp;
int year = 0;

//hashed url cpy
char vhashed_url[41] = {};
char vhashed_dir[4] = {};
char vhashed_dir_[41] = {};
//////////////////////////////////////////////////////////////////
// void *thr_hit(void *arg)           				//
// =============================================================//
// Input: void* arg -> url				  	//	  
// Output: 0					   		//
//////////////////////////////////////////////////////////////////
void *thr_hit(void *arg)
{
  tid = pthread_self();//thread ID return
  printf("*PID# %d create the *TID# %u\n",getpid(),(unsigned int)tid);//print terminal
  fprintf(flog, "[Hit]%s/%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n", vhashed_dir, vhashed_dir_, year, ltp->tm_mon + 1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec); //write "[Hit]" in logfile.txt
  fprintf(flog, "[Hit]%s\n", (char*)arg); //write in logfile.txt
  return((void*)0); //return 0
}
//////////////////////////////////////////////////////////////////
// void *thr_miss(void *arg)                			//
// =============================================================//
// Input: void* arg -> url				  	//	  
// Output: void					   		//
//////////////////////////////////////////////////////////////////
void *thr_miss(void *arg)
{
  tid = pthread_self(); //thread ID return
  printf("*PID# %d create the *TID# %u\n",getpid(),(unsigned int)tid);//print termianl
  fprintf(flog, "[Miss]%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n", (char*)arg, year, ltp->tm_mon + 1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec); //write "[Miss]" in logfile.txt
  return((void*)0);
}
//////////////////////////////////////////////////////////////////
// void p(int semid)                				//
// =============================================================//
// Input: strcut sembuf pbuf -> semaphore structual buffer  	//	  
// Output: void					   		//
//////////////////////////////////////////////////////////////////
void p(int semid)
{
	struct sembuf pbuf;
	pbuf.sem_num = 0; //semaphore number
	pbuf.sem_op = -1; //semaphore operation
	pbuf.sem_flg = SEM_UNDO; //semaphore flag, auto clear
	if((semop(semid, &pbuf,1)) == -1) //perform a series of operations on a semaphore set
	{
		perror("p: semop failed"); //error
		exit(1);
	}
	 printf("*PID# %d in the critical zone.\n", getpid()); //print in terminal
}
//////////////////////////////////////////////////////////////////
// void v(int semid)                				//
// =============================================================//
// Input: strcut sembuf pbuf -> semaphore structual buffer  	//	  
// Output: void					   		//
//////////////////////////////////////////////////////////////////
void v(int semid)
{
	struct sembuf vbuf;
	vbuf.sem_num = 0; //semaphore number
	vbuf.sem_op = 1; //semaphore operation
	vbuf.sem_flg = SEM_UNDO;//semaphore flag
	if((semop(semid, &vbuf,1)) == -1) //semaphore
	{
		perror("v : semop failed"); //error
		exit(1);
	}
	 printf("*PID# %d exited the critical zone.\n", getpid());//print in terminal
}

//////////////////////////////////////////////////////////////////
// char* getHomeDir                				//
// =============================================================//
// Input: char* home -> Insert char           			//
// Output: char* home -> home directory   return   		//
//////////////////////////////////////////////////////////////////
char *getHomeDir(char *home) {
   struct passwd *usr_info = getpwuid(getuid()); //user informaiton get
   strcpy(home, usr_info->pw_dir); //home directory cpy

   return home; //return char home
}

//////////////////////////////////////////////////////////////////
// char *sha1_hash                  				//
// =============================================================//
// Input: char *input_url -> data to hashing       		//
//     hashed_160bits[20] -> save Hexadecimal data     		//
//     int i -> count number             			//
// Output: char *hashed_url -> hashed URL conversed Hexadecimal //
//////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url) {
   unsigned char hashed_160bits[20] = {}; //save hexadecimal data
   char hashed_hex[41] = {}; //hexadecimal data
   int i; //count number

   SHA1(input_url, strlen(input_url), hashed_160bits); //hashing function SHA1

   for (i = 0; i<sizeof(hashed_160bits); i++) //for
      sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]); //change hexadecimal data

   strcpy(hashed_url, hashed_hex); //hashed_hex cpy to hashed_url

   return hashed_url; //return hashed_url
}
//////////////////////////////////////////////////////////////////
// char* getIPAddr                  //
// =============================================================//
// Input: struct hostent* hent -> hostent struct      //
//     char* haddr -> decimal string            //
//     int len -> strlen(address)            //
// Output: char* home -> home directory   return         //
//////////////////////////////////////////////////////////////////
char* getIPAddr(char *addr)
{
   struct hostent* hent;
   char* haddr;
   int len = strlen(addr);

   if ((hent = (struct hostent*)gethostbyname(addr)) != NULL) //url -> struct hostent
   {
      haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));//hostent struct IP address -> network byte order IP address -> dotted decimal stirng
   }
   return haddr;//dotted decimal string return
}
//////////////////////////////////////////////////////////////////
// void my_exit(int singo)               //
// =============================================================//
// Input: x                      //
// Output: x                     //
//////////////////////////////////////////////////////////////////
void my_exit(int signo)
{
   printf("\n");
   time(&end); //process end time
   fprintf(flog, "**SERVER** [Terminated] run time: %.0fsec. #sub process: %d\n", difftime(end, start), pnum);//logfile
   exit(0);//end
}
//////////////////////////////////////////////////////////////////
// void my_alarm(int singo)               			//
// =============================================================//
// Input: response_header -> response message header            //
//	  response_message -> response message NO RESPONSE	//
// Output: x          					        //
//////////////////////////////////////////////////////////////////
void my_alarm(int signo)
{
   char response_header[BUFFSIZE] = { 0, };
   char response_message[BUFFSIZE] = { 0, };
   sprintf(response_message, "<h1>NO RESPONSE</h1><br>"); //NO RESPONSE
   sprintf(response_header, "HTTP/1.0 200 OK\r\n"
      "Server:2018 simple web server\r\n"
      "Content-length:%lu\r\n"
      "Content-type:text/html\r\n\r\n", strlen(response_message)); //response_header
   write(client_fd, response_header, strlen(response_header));//printf message
   write(client_fd, response_message, strlen(response_message));//printf message

   close(client_fd); //client close
   close(socket_fd); //close main server
   exit(0);//end   
}
///////////////////////////////////////////////////////////////////////////
// static void hanlder()               					 //
// ======================================================================//
// Input: pid_t pid -> process id                			 //
//     int status -> process status                			 //
// Output: void                         				 //
///////////////////////////////////////////////////////////////////////////
static void handler()
{
   pid_t pid;
   int status;
   while ((pid = waitpid(-1, &status, WNOHANG)) >0); //parents process wait
}
//////////////////////////////////////////////////////////////////////////////////
// int main()                          						//
// =============================================================================//
// Input: struct sockaddr_in server_addr, client_addr -> server, clinet address //
//   int socket_fd, client_fd -> socket number     			        //
//   int len, len_out -> lenth               					//
//   char buf[BUFFSIZE] -> input buffer       				        //
//   pid_t pid -> process ID                					//
//   FILE *flog -> log file              					//
//   char log[41] = {} -> log              					//
//   time_t now -> now time                 					//
//   struct tm *ltp -> local time            					//
//   int Hit = 0 -> count hit                					//
//   int Miss = 0 -> count miss               					//
//   time_t start,end -> start & end time           				//
//   char *str -> char string port number              				//
//   int s -> signal                       					//
//   struct in_addr inet_client_address ->client address     			//
//   char response_header[BUFFSIZE] = {0, } -> http header      		//
//   char response_message[BUFFSIZE] = {0, } -> http message      		//
//   char tmp[BUFFSIZE] = {0, } -> bufffer token        			//
//   char method[20] = {0, } -> http method            				//
//   char url[BUFFSIZE] = {0, } -> url              				//
//   char * tok = NULL -> token                 				//
//   int semid -> semaphore id 							//
// Output: 0 -> end                     					//
//////////////////////////////////////////////////////////////////////////////////
int main()
{
   int i = 0;
   struct sockaddr_in server_addr, client_addr;
   int len, len_out;
   pid_t pid;

   FILE *fp;
   int ff;
   DIR *pDir;
   DIR *pD;

   char log[41] = {};

   char *str;

   char home[41] = {}; 
    char hashed_url[41] = {};
    char hashed_dir[4] = {};
    char hashed_dir_[41] = {};
   struct dirent *pFile;
   struct dirent *pF;
  

   int semid;
   union semun{
  	int val; //semphore value
	  struct semid_ds *buf;
	  unsigned short int *array;
   }arg;

   time(&start); //program start time

   getHomeDir(log); //home directory

   umask(000);//Authority control function

   strcat(log, "/logfile"); //directory path setting: /home/logfile
   mkdir(log, 0777); //make directory "logfile"
   strcat(log, "/logfile.txt"); //directory path setting: /home/logfile/logfile.txt
   flog = fopen(log, "a"); //file open "logfile.txt"

   getHomeDir(home); //home directory
   strcat(home, "/cache"); //directory path setting: /home/cache      
   mkdir(home, 0777); //make directory /home/cache

   if((semid = semget((key_t)38055,1,IPC_CREAT|0666)) == -1)//semaphore 구별 ID
   {
    	perror("semget failed");
    	exit(1);
   }
   arg.val = 1; //result val
   if((semctl(semid,0,SETVAL,arg)) == -1) //semaphore 제어
   {
    	perror("semctl failed");
	    exit(1);
   }
   if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) { //socket open & if socket error
      printf("Server: Cant' opne stream socket.");
      return 0;
   }

   int opt = 1; //option number
   setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));   //avoid bind error

   bzero((char*)&server_addr, sizeof(server_addr)); //initialize
   server_addr.sin_family = AF_INET;//address
   server_addr.sin_addr.s_addr = htonl(INADDR_ANY);//32bits IP address
   server_addr.sin_port = htons(PORTNO); //16bits port number
   if (bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))<0) { //Assign ip, port number in socket
      printf("Server: Can't bind local address.\n"); //bind error
      close(socket_fd);
      return 0;
   }


   listen(socket_fd, 5); //change listen for connection as queue lenth of 5 as
   signal(SIGCHLD, (void *)handler); //parents wait

   signal(SIGINT, my_exit); //ctrl + c signal
   while (1) {
      struct in_addr inet_client_address;
      char buf[BUFFSIZE];
      char response_header[BUFFSIZE * 20] = { 0, };
      char tmp[BUFFSIZE] = { 0, };
      char method[20] = { 0, };
      char url[BUFFSIZE] = { 0, };
      char url2[BUFFSIZE] = { 0, };
      char * tok = NULL;
      int s = 0;
      char strc[BUFFSIZE] = { 0, };

      bzero((char*)&client_addr, sizeof(client_addr));//initialize
      len = sizeof(client_addr);//lenth of client_addr
      client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);//server receive chlient access
      if (client_fd<0) {//client acess error
         printf("Server: accept failed. \n");
         close(socket_fd);
         return 0;
      }

      inet_client_address.s_addr = client_addr.sin_addr.s_addr; //internet address = clinet address

      str = inet_ntoa(client_addr.sin_addr); //network address -> dotted decimal char*
      strcpy(strc, str); //cpy
      //printf("[%s:%d] client was conneted. \n", strc, client_addr.sin_port); //print connected
      len_out = read(client_fd, buf, BUFFSIZE); //client_fd read
      strcpy(tmp, buf); //cpy buffer
      tok = strtok(tmp, " "); //tok = tpm token

      strcpy(method, tok); //http method
      if (strcmp(method, "GET") == 0) //method == GET
      {
         tok = strtok(NULL, " "); //token url
         strcpy(url, tok); //url cpy
	        pnum++;//sub server number
      }
      else //else
      {
        //printf("[%s:%d] client was disconnected. \n", strc, client_addr.sin_port);//disconnectd
        //continue;//skip
      }

      int count = 0;
      pid = fork(); //create chiled process

      if (pid == -1) //fork error
      {
         printf("erreor pid\n");
         close(client_fd);
         close(socket_fd);
         break;
      }
      if (pid == 0) //child process
      {
	if(!strcmp(method, "GET") == 0) //if method is not GET
	{
		exit(0); //terminated
	}
	
	
         strcpy(url2, url);//url2 = http://~

         tok = strtok(url, ":");
         tok = strtok(NULL, "/");//token url

         strcpy(url, tok);//url = www.~
         
  /*          puts("=================================================");
            printf("Request from [%s : %d]\n", inet_ntoa(inet_client_address), client_addr.sin_port);//IP address, port
            puts(buf); //print buffer
            puts("=================================================");*/
         

         time(&now); //current time function
         ltp = localtime(&now); //localtime

         year = 1900 + ltp->tm_year; //today year

         sha1_hash(url2, hashed_url); //url hashing

         for (i = 0; i<3; i++)
            hashed_dir[i] = hashed_url[i]; //cpy previous 3 alphabet of hashing data

         hashed_dir[3] = '\0'; //insert NULL

         for (i = 3; i<strlen(hashed_url); i++)
            hashed_dir_[i - 3] = hashed_url[i]; //cpy hashing url removed previous 3 alphabet 

         ///////////////assginment 1-2/////////////////
         pDir = opendir(home); //open home directory

         for (pFile = readdir(pDir); pFile; pFile = readdir(pDir)) //read directory pDir and repeat
         {
            if (strcmp(pFile->d_name, hashed_dir) == 0) //if pFile name same previous 3 alphabet
            {
               strcat(home, "/");
               strcat(home, hashed_dir); //directory path = /home/cache/hashed_dir
               pD = opendir(home); //open directory /home/cache/hashed_dir

               for (pF = readdir(pD); pF; pF = readdir(pD)) //read directory pD and repeat
               {
                  if (strcmp(pF->d_name, hashed_dir_) == 0) //if pF name same hashing url
                  {
                     strcat(home, "/");
                     strcat(home, hashed_dir_);
                     s = 1; //sginal = Hit
                     break; //repeat break
                  }
               }
            }
         }
	  printf("*PID# %d is waiting for the semaphore\n",getpid()); //p에 접근
	
         if (s == 1) //if Hit
         { 
	   //hashed url cpy
           strcpy(vhashed_url,hashed_url);
           strcpy(vhashed_dir_,hashed_dir);
           strcpy(vhashed_dir_,hashed_dir_);

            fp = fopen(home,"r");//read file open

            while(!feof(fp))//when file end
            {
               fgets(tmp,sizeof(response_header),fp);//read file
               strcat(response_header,tmp);//response_header
            }

        	write(client_fd, response_header, strlen(response_header));//print header
 		p(semid); //semaphore access
       		int err;
		err = pthread_create(&tid,NULL,thr_hit,(void*)url2); //threads hit
		if(err != 0){
			printf("pthread_create() error.\n");
			return 0;
	  	}
	   
            
            closedir(pD); //close directory pD

            closedir(pDir); //closed directory pDir
	
         }

         else if (s == 0) //if miss
         {

            getHomeDir(home);//home directory
            strcat(home, "/cache/"); //directory path setting: /home/cache
            strcat(home, hashed_dir); //directory pathe setting: /home/cache/hashed_dir


            mkdir(home, 0777); //make directory home

            strcat(home, "/"); //directory path setting: /home/cache/hashed_dir/
            strcat(home, hashed_dir_); //directory path setting: /home/cache/hashed_dir/hashed_dir_
            fp = fopen(home, "a"); //file open "hashed_dir_"

            char* getHost;
            struct sockaddr_in webserver_addr;//webserver socket address
            int websocket_fd;//webserver socket descriptor

            if ((websocket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) { //socket open & if socket error
               printf("Server: Cant' opne stream socket.");
               return 0;
            }
            getHost = getIPAddr(url); //changing url to IP

            bzero((char*)&webserver_addr, sizeof(webserver_addr)); //initialize
            webserver_addr.sin_family = AF_INET;//address
            webserver_addr.sin_addr.s_addr = inet_addr(getHost);;//32bits IP address
            webserver_addr.sin_port = htons(80); //16bits port number


            if (connect(websocket_fd, (struct sockaddr *)&webserver_addr, sizeof(webserver_addr))<0)//connect webserver socket and webserver address
            {
               printf("can't connect\n");
               break;
            }
            write(websocket_fd, buf, BUFFSIZE);//transmit buf to webserver
            signal(SIGALRM, my_alarm);//alarm signal
            alarm(10);//alarm after 10 sec


            while (read(websocket_fd, response_header, BUFFSIZE * 20)>0) { // proxy server reads response from web server
               fprintf(fp, "%s", response_header);
               write(client_fd, response_header, strlen(response_header)); // write reponse_message
               bzero(response_header, sizeof(response_header));
	
            }
		
            alarm(0); //alarm clear
	 
	   p(semid); //use shared resource in semaphore
   	   int err;
	   err = pthread_create(&tid,NULL,thr_miss,(void*)url2); //threads
	   if(err != 0){
		printf("pthread_create() error.\n");
		return 0;
	   }
	   
            fclose(fp);//close fp
            close(websocket_fd);//close web server
         }//Miss end
         pthread_join(tid,NULL);
         printf("*TID# %u is exited.\n",(unsigned int)tid);
	 v(semid); //not use shared resource in semaphore
         close(client_fd); //client close
         exit(0); //sub server exit
      }

   }//parents process 

   close(socket_fd); //close main server
   return 0;
}
