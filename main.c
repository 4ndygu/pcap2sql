/*
  pcap2sql
  Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>

  This program uses libnids to iterate through a pcap file and reassamble IP/TCP/UDP payload data and stores the
  resulting data streams and packet information in a relational database by calling the Java code in pcap2sql-bridge
  through JNI.

  The Java code decouples the database access from this code by providing helper functions and transparently persisted
  objects with simple getter and setter methods that map to the database using EclipseLink.

  For calling Java methods, there are several "proxy" functions defined below in the form of <class name>_<method
  name>. They accept and return conventional C types and have the necessary JNI boilerplate.

  Because the processing is sequential, to avoid constantly passing object references, references to key types of
  objects are held by global jobjectholder and persistentobject structs. After entering a libnids callback, the global
  reference is set to the actual persistent object that map to the database records of the network data being
  processed. The proxy functions are using these references to invoke Java methods.

*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "nids.h"
#include "jni.h"


#define logf(fmt, ...) fprintf(stderr, "[%lu] %s:%u: %s: " fmt "\n", (unsigned long) time(NULL), __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log(s) logf("%s", s)

#define die(s)					\
  log("FATAL: " s);				\
  exit(EXIT_FAILURE);

/* All exception to occur in this code are most likely not recoverable. This macro checks for them and shuts the JVM
   down cleanly. */
#define e()					\
  if ((*jni)->ExceptionOccurred(jni) != NULL) { \
    log("FATAL: exception in the jvm");		\
    (*jni)->ExceptionDescribe(jni);		\
    jvm_shutdown();				\
    exit(EXIT_FAILURE);				\
  }

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&x))

#define usage()								      \
  fprintf(stderr, "usage: %s -d <working directory> <pcap file>\n", argv[0]); \
  exit(EXIT_FAILURE);

#define hexdump(offset, len)			\
  FILE *hexdump = popen("hexdump -C >&2", "w");	\
  fwrite(offset, 1, len, hexdump);		\
  fclose(hexdump);

struct jobjectholder {
  jclass class;
  jobject object;
};

typedef struct jobjectholder persistentobject;

/* tuple for indentifiying a unique Ip4Stream record: source address, destination address, protocol */
struct tuple3 {
  u_int saddr;
  u_int daddr;
  u_int8_t ip_p;
};


/* globals */
JavaVM *jvm;
JNIEnv *jni;

char inputfile[PATH_MAX];
char workdir[PATH_MAX];

persistentobject Ip4Stream;
persistentobject Tcp4Connection;
persistentobject Udp4Stream;
struct jobjectholder Util;


/* utility functions */

int jvm_start(char *classpath) {
  JavaVMInitArgs vmargs;
  JavaVMOption options[4];
  int n_options = 0;
  int res;
  char *buf_opt_classpath;
  int i;

  /* set the class path */
  buf_opt_classpath = malloc(4096);
  snprintf(buf_opt_classpath, 4096, "-Djava.class.path=%s", classpath);
  options[0].optionString = buf_opt_classpath;
  n_options++;
  /* additional options */
  /* options[1].optionString = ""; */
  /* n_options++; */
  /* additional options */
  options[1].optionString = "-Xmx" MAXHEAP "m";
  n_options++;
  vmargs.version  = JNI_VERSION_1_4;
  vmargs.options  = options;
  vmargs.nOptions = n_options;
  vmargs.ignoreUnrecognized = JNI_TRUE;

  for (i = 0; i < vmargs.nOptions; i++) {
    logf("option set: %s", vmargs.options[i].optionString);
  }

  log("starting the jvm");
  res = (int) JNI_CreateJavaVM(&jvm, (void **)&jni, &vmargs);
  logf("JNI_CreateJavaVM() returned %d, returning it", res);
  free(buf_opt_classpath);
  return res;
}

int jvm_shutdown() {
  int res;

  log("shutting down the jvm");
  res = (int) (*jvm)->DestroyJavaVM(jvm);
  logf("DestroyJavaVM() returned %d, returning it", res);
  return res;
}

/* initialize global class pointers */
void init_jobjectholders() {
  Ip4Stream.class = (*jni)->FindClass(jni, "pcap2sql/orm/Ip4Stream");
  e();
  Tcp4Connection.class = (*jni)->FindClass(jni, "pcap2sql/orm/Tcp4Connection");
  e();
  Udp4Stream.class = (*jni)->FindClass(jni, "pcap2sql/orm/Udp4Stream");
  e();
  Util.class = (*jni)->FindClass(jni, "pcap2sql/Util");
  e();
  return;
}

const char *to_streamfile_path(int id) {
  static char path[PATH_MAX];
  char buf[64];
  strncpy(path, workdir, PATH_MAX - 64);
  sprintf(buf, "/stream_%d", id);
  strcat(path, buf);
  return (const char *) &path;
}

const char *to_tuple4string(struct tuple4 addr)
{
  static char buf[64];
  strcpy (buf, int_ntoa(addr.daddr));
  sprintf (buf + strlen(buf), ":%i ", addr.dest);
  strcat (buf, int_ntoa(addr.saddr));
  sprintf (buf + strlen(buf), ":%i", addr.source);
  return buf;
}

const char *to_tuple3string(struct tuple3 t3)
{
  static char buf[64];
  strcpy (buf, int_ntoa(t3.daddr));
  sprintf (buf + strlen(buf), " %s ", int_ntoa(t3.saddr));
  sprintf (buf + strlen(buf), "%u", t3.ip_p);
  return buf;
}

/* converts struct timeval to java.sql.Timestamp */
jobject to_Timestamp(struct timeval *ts) {
  jclass clazz;
  jmethodID method;
  jobject object;
  
  /* tv_sec holds the seconds elapsed since the epoch.  */
  /* It must be converted as Timestamp takes milliseconds. */
  jlong timeInt = ts->tv_sec * 1000;
  /* tv_usec is the fractional part in milliseconds precision. */
  /* It must be converted as Timestamp has a fractional part in nanoseconds precision. */
  jint timeFrac = ts->tv_usec * 1000;

  clazz = (*jni)->FindClass(jni, "java/sql/Timestamp");
  e();
  method = (*jni)->GetMethodID(jni, clazz, "<init>", "(J)V");
  e();
  object = (*jni)->NewObject(jni, clazz, method, timeInt);
  e();
  method = (*jni)->GetMethodID(jni, clazz, "setNanos", "(I)V");
  e();
  (*jni)->CallVoidMethod(jni, object, method, timeFrac);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, clazz);

  return object;
}

int open_streamfile(int streamId) {
  int fd = open(to_streamfile_path(streamId), O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (fd == -1) {
    logf("failed to open %s for writing: %s", to_streamfile_path(streamId), strerror(errno));
    return fd;
  }
  logf("opened %s for writing", to_streamfile_path(streamId));
  return fd;
}


/* generic proxy functions mapping to common methods of Ip4Stream and other entity classes, they are not used directly  */

int _getId(persistentobject o) {
  jmethodID method = (*jni)->GetMethodID(jni, o.class, "getId", "()I");
  e();
  return (int) (*jni)->CallIntMethod(jni, o.object, method);
}

void _addStreamSegment(persistentobject o, int length, struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, o.class, "addStreamSegment", "(ILjava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, o.object, method, (jint) length, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void _setLastTime(persistentobject o, struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, o.class, "setLastTime", "(Ljava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, o.object, method, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void _setData(persistentobject o, const char *path) {
  jmethodID method = (*jni)->GetMethodID(jni, o.class, "setData", "(Ljava/lang/String;)V");
  e();
  jstring argPath = (*jni)->NewStringUTF(jni, path);
  e();
  (*jni)->CallVoidMethod(jni, o.object, method, argPath);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argPath);

  return;
}

/* class specific proxy functions */

int Ip4Stream_getId() {
  return _getId(Ip4Stream);
}

void Ip4Stream_addStreamSegment(int length, struct timeval *ts) {
  _addStreamSegment(Ip4Stream, length, ts);
}

void Ip4Stream_setLastTime(struct timeval *ts) {
  _setLastTime(Ip4Stream, ts);
}

void Ip4Stream_setData(const char *path) {
  _setData(Ip4Stream, path);
}

int Tcp4Connection_getId() {
  return _getId(Tcp4Connection);
}

int Tcp4Connection_getOutStreamId() {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "getOutStreamId", "()I");
  e();
  return (int) (*jni)->CallIntMethod(jni, Tcp4Connection.object, method);
}

int Tcp4Connection_getInStreamId() {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "getInStreamId", "()I");
  e();
  return (int) (*jni)->CallIntMethod(jni, Tcp4Connection.object, method);
}

void Tcp4Connection_setLastTime(struct timeval *ts) {
  _setLastTime(Tcp4Connection, ts);
}

void Tcp4Connection_setOutStreamLastTime(struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "setOutStreamLastTime", "(Ljava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void Tcp4Connection_setInStreamLastTime(struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "setInStreamLastTime", "(Ljava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void Tcp4Connection_addOutStreamSegment(int length, struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "addOutStreamSegment", "(ILjava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, (jint) length, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void Tcp4Connection_addInStreamSegment(int length, struct timeval *ts) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "addInStreamSegment", "(ILjava/sql/Timestamp;)V");
  e();
  jobject argTime = to_Timestamp(ts);
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, (jint) length, argTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argTime);

  return;
}

void Tcp4Connection_setOutStreamData(const char *path) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "setOutStreamData", "(Ljava/lang/String;)V");
  e();
  jstring argPath = (*jni)->NewStringUTF(jni, path);
  e();
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, argPath);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argPath);

  return;
}

void Tcp4Connection_setInStreamData(const char *path) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "setInStreamData", "(Ljava/lang/String;)V");
  e();
  jstring argPath = (*jni)->NewStringUTF(jni, path);
  e();
  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, argPath);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, argPath);

  return;
}

void Tcp4Connection_setFinalStatus(int finalStatus) {
  jmethodID method = (*jni)->GetMethodID(jni, Tcp4Connection.class, "setFinalStatus", "(I)V");
  e();

  (*jni)->CallVoidMethod(jni, Tcp4Connection.object, method, (jint) finalStatus);
  e();
}

int Udp4Stream_getId() {
  return _getId(Udp4Stream);
}

int Udp4Stream_getStreamId() {
  jmethodID method = (*jni)->GetMethodID(jni, Udp4Stream.class, "getStreamId", "()I");
  e();
  return (int) (*jni)->CallIntMethod(jni, Udp4Stream.object, method);
}

void Udp4Stream_addStreamSegment(int length, struct timeval *ts) {
  _addStreamSegment(Udp4Stream, length, ts);
}

void Udp4Stream_setLastTime(struct timeval *ts) {
  _setLastTime(Udp4Stream, ts);
}

void Udp4Stream_setData(const char *path) {
  _setData(Udp4Stream, path);
}


/* Util's peristent object "factories" */

jobject Util_newIp4Stream(struct tuple3 t3, struct timeval *ts) {
  jmethodID method;
  jobject res;

  jstring destIp, sourceIp;
  jint proto;
  jobject firstTime;

  destIp = (*jni)->NewStringUTF(jni, int_ntoa(t3.daddr));
  e();
  sourceIp = (*jni)->NewStringUTF(jni, int_ntoa(t3.saddr));
  e();
  proto = t3.ip_p;
  firstTime = to_Timestamp(ts);

  method = (*jni)->GetMethodID(jni, Util.class, "newIp4Stream", "(Ljava/lang/String;Ljava/lang/String;ILjava/sql/Timestamp;)Lpcap2sql/orm/Ip4Stream;");
  e();

  res = (*jni)->CallObjectMethod(jni, Util.object, method, destIp, sourceIp, proto, firstTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, destIp);
  (*jni)->DeleteLocalRef(jni, sourceIp);
  (*jni)->DeleteLocalRef(jni, firstTime);

  return res;  
}

jobject Util_newTcp4Connection(struct tuple4 addr, struct timeval *ts) {
  jmethodID method;
  jobject res;

  jstring destIp, sourceIp;
  jint destPort, sourcePort;
  jobject firstTime;

  destIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.daddr));
  e();
  sourceIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.saddr));
  e();
  destPort = addr.dest;
  sourcePort = addr.source;
  firstTime = to_Timestamp(ts);

  method = (*jni)->GetMethodID(jni, Util.class, "newTcp4Connection", "(Ljava/lang/String;Ljava/lang/String;IILjava/sql/Timestamp;)Lpcap2sql/orm/Tcp4Connection;");
  e();

  res = (*jni)->CallObjectMethod(jni, Util.object, method, destIp, sourceIp, destPort, sourcePort, firstTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, destIp);
  (*jni)->DeleteLocalRef(jni, sourceIp);
  (*jni)->DeleteLocalRef(jni, firstTime);

  return res;
}

jobject Util_newUdp4Stream(struct tuple4 addr, struct timeval *ts) {
  jmethodID method;
  jobject res;

  jstring destIp, sourceIp;
  jint destPort, sourcePort;
  jobject firstTime;

  destIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.daddr));
  e();
  sourceIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.saddr));
  e();
  destPort = addr.dest;
  sourcePort = addr.source;
  firstTime = to_Timestamp(ts);

  method = (*jni)->GetMethodID(jni, Util.class, "newUdp4Stream", "(Ljava/lang/String;Ljava/lang/String;IILjava/sql/Timestamp;)Lpcap2sql/orm/Udp4Stream;");
  e();

  res = (*jni)->CallObjectMethod(jni, Util.object, method, destIp, sourceIp, destPort, sourcePort, firstTime);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, destIp);
  (*jni)->DeleteLocalRef(jni, sourceIp);
  (*jni)->DeleteLocalRef(jni, firstTime);

  return res;
}


/* Proxy functions for Util's interface for looking up objects */

jobject Util_findTcp4Connection(int id) {
  jmethodID method;
  jobject res;

  jint argId = id;

  method = (*jni)->GetMethodID(jni, Util.class, "findTcp4Connection", "(I)Lpcap2sql/orm/Tcp4Connection;");
  e();
  
  res = (*jni)->CallObjectMethod(jni, Util.object, method, argId);
  e();

  return res;
}

jobject Util_findIp4Stream(struct tuple3 t3) {
  jmethodID method;
  jobject res;

  jstring destIp, sourceIp;
  jint proto;

  destIp = (*jni)->NewStringUTF(jni, int_ntoa(t3.daddr));
  e();
  sourceIp = (*jni)->NewStringUTF(jni, int_ntoa(t3.saddr));
  e();
  proto = t3.ip_p;

  method = (*jni)->GetMethodID(jni, Util.class, "findIp4Stream", "(Ljava/lang/String;Ljava/lang/String;I)Lpcap2sql/orm/Ip4Stream;");
  e();
  
  res = (*jni)->CallObjectMethod(jni, Util.object, method, destIp, sourceIp, proto);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, destIp);
  (*jni)->DeleteLocalRef(jni, sourceIp);

  return res;
}

jobject Util_findUdp4Stream(struct tuple4 addr) {
  jmethodID method;
  jobject res;

  jstring destIp, sourceIp;
  jint destPort, sourcePort;

  destIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.daddr));
  e();
  sourceIp = (*jni)->NewStringUTF(jni, int_ntoa(addr.saddr));
  e();
  destPort = addr.dest;
  sourcePort = addr.source;

  method = (*jni)->GetMethodID(jni, Util.class, "findUdp4Stream", "(Ljava/lang/String;Ljava/lang/String;II)Lpcap2sql/orm/Udp4Stream;");
  e();
  
  res = (*jni)->CallObjectMethod(jni, Util.object, method, destIp, sourceIp, destPort, sourcePort);
  e();

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, destIp);
  (*jni)->DeleteLocalRef(jni, sourceIp);

  return res;
}

jobject Util_iterateAllNonTcp4Streams() {
  jmethodID method;
  jobject res;

  method = (*jni)->GetMethodID(jni, Util.class, "iterateAllNonTcp4Streams", "()Lpcap2sql/orm/Ip4Stream;");
  e();
  res = (*jni)->CallObjectMethod(jni, Util.object, method);
  e();
  
  return res;
}


/* callback funtions */

void ip4_callback(struct ip *a_packet, int len) {
  int fd, id, res;
  struct tuple3 t3;
  char tuple3string[64];
  int headerlen, payloadlen;

  /* no TCP or UDP */
  if (a_packet->ip_p == IPPROTO_TCP || a_packet->ip_p == IPPROTO_UDP) {
    return;
  }

  /* ...just for the record: a_packet holds the whole packet, not just the header.
     That means the payload is at the offset a_packet + a_packet->ip_hl * 4. */

  /* roll a tuple3 */
  t3.saddr = *((u_int *) &a_packet->ip_src);
  t3.daddr = *((u_int *) &a_packet->ip_dst);
  t3.ip_p = a_packet->ip_p;

  strncpy(tuple3string, to_tuple3string(t3), sizeof(tuple3string)); // hold it locally

  /* instantiate a new persistent object or get already stored one for this tuple3 */
  Ip4Stream.object = Util_findIp4Stream(t3);
  if (Ip4Stream.object == NULL) {
    logf("%s object not found in database, instantiating a new one", tuple3string);
    Ip4Stream.object = Util_newIp4Stream(t3, &(nids_last_pcap_header->ts));
    logf("%s object successfuly instantiated (id = %u)", tuple3string, Ip4Stream_getId());
  } else {
    logf("%s object found in database, (id = %u)", tuple3string, Ip4Stream_getId());
  }

  id = Ip4Stream_getId();

  headerlen = a_packet->ip_hl * 4;
  payloadlen = ntohs(a_packet->ip_len) - headerlen;

  /* dump payload to file */
  fd = open_streamfile(id);
  if (fd != -1) {
    res = write(fd, (void *) a_packet + headerlen, payloadlen);
    if (res != -1) {
      logf("%s (id = %u) written %u bytes to %s", tuple3string, id, payloadlen, to_streamfile_path(id));
      /* creating new StreamSegment record, if new data is successfully written */
      Ip4Stream_addStreamSegment(payloadlen, &nids_last_pcap_header->ts);
    }
    close(fd);
  }
  /* further error handling in open_streamfile() */

  /* finally, set lastTime */
  Ip4Stream_setLastTime(&(nids_last_pcap_header->ts));

  // DEBUG
  // hexdump((void *) a_packet + headerlen, payloadlen);

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, Ip4Stream.object);

  return;
}

void tcp4_callback(struct tcp_stream *a_tcp, int **id) {
  int streamId;
  char tuple4string[64];
  int fd;

  strncpy(tuple4string, to_tuple4string(a_tcp->addr), sizeof(tuple4string)); // hold it locally

  /* in this case the actual connection's persistent object should already exist */
  if (a_tcp->nids_state != NIDS_JUST_EST) {
    Tcp4Connection.object = Util_findTcp4Connection(**id);
  }

  /* newly established connection */
  if (a_tcp->nids_state == NIDS_JUST_EST) {

    /* instantiate new a Tcp4Connection object */    
    logf("NIDS_JUST_EST: %s instantiating new object", tuple4string);
    Tcp4Connection.object = Util_newTcp4Connection(a_tcp->addr, &(nids_last_pcap_header->ts));
    /* libnids gives us a unique pointer to a custom location, retain persistent object's id there */
    *id =  (int *) malloc(sizeof(int));
    **id = Tcp4Connection_getId();
    logf("NIDS_JUST_EST: %s object successfuly instantiated (id = %u, outStreamId = %u, inStreamId = %u)", tuple4string, **id, Tcp4Connection_getOutStreamId(), Tcp4Connection_getInStreamId());

    /* set flags to get data */
    a_tcp->client.collect++; // we want data received by a client
    a_tcp->server.collect++; // and by a server, too
    //a_tcp->server.collect_urg++; // urgent data received by a server
    //a_tcp->client.collect_urg++; // urgent data received by a client

    /* create files for outStreamId and inStreamId data */
    streamId = Tcp4Connection_getOutStreamId();
    logf("NIDS_JUST_EST: %s creating file for outStream data", tuple4string);
    fd = open_streamfile(streamId);
    if (fd != -1) {
      close(fd);
    }

    streamId = Tcp4Connection_getInStreamId();
    logf("NIDS_JUST_EST: %s creating file for inStream data", tuple4string);
    fd = open_streamfile(streamId);
    if (fd != -1) {
      close(fd);
    }

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Tcp4Connection.object);

    return;
  }

  /* connection has been closed normally */
  if (a_tcp->nids_state == NIDS_CLOSE) {
    //id = Tcp4Connection_getId();
    logf("NIDS_CLOSE: %s (id = %u)", tuple4string, **id);

    /* set finalStatus and lastTime */
    Tcp4Connection_setFinalStatus(0);
    Tcp4Connection_setLastTime(&(nids_last_pcap_header->ts));

    /* save streamdump in the DB */
    streamId = Tcp4Connection_getOutStreamId();
    Tcp4Connection_setOutStreamData(to_streamfile_path(streamId));
    streamId = Tcp4Connection_getInStreamId();
    Tcp4Connection_setInStreamData(to_streamfile_path(streamId));

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Tcp4Connection.object);

    return;
  }

  /* connection has been closed by RST */
  if (a_tcp->nids_state == NIDS_RESET) {
    //id = Tcp4Connection_getId();
    logf("NIDS_RESET: %s (id = %u)", tuple4string, **id);

    /* set finalStatus and lastTime */
    Tcp4Connection_setFinalStatus(1);
    Tcp4Connection_setLastTime(&(nids_last_pcap_header->ts));

    /* save stream dump in the DB */
    streamId = Tcp4Connection_getOutStreamId();
    Tcp4Connection_setOutStreamData(to_streamfile_path(streamId));
    streamId = Tcp4Connection_getInStreamId();
    Tcp4Connection_setInStreamData(to_streamfile_path(streamId));

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Tcp4Connection.object);

    return;
  }

  /* new data flows through */
  if (a_tcp->nids_state == NIDS_DATA) {
    int fd, res;
    struct half_stream *hlf;

    //id = Tcp4Connection_getId();
            
    /* // urgent? */
    /* if (a_tcp->server.count_new_urg) { */
    /*   // new byte of urgent for the server */
    /*   // a_tcp->server.urgdata; */
    /*   return; */
    /* } */

    if (a_tcp->server.count_new) { // data for server
      hlf = &a_tcp->server; // stream out
      logf("NIDS_DATA: %s (id = %u) %u bytes out", tuple4string, **id, hlf->count_new);
      /* dump new data file */
      streamId = Tcp4Connection_getOutStreamId();
      fd = open_streamfile(streamId);
      if (fd != -1) {
	res = write(fd, hlf->data, hlf->count_new);
	if (res != -1) {
	  logf("NDIS_DATA: %s (id = %u) written %u bytes to %s", tuple4string, **id, res, to_streamfile_path(streamId));
	  /* creating new OutStreamSegment record, if new data is successfully written */
	  Tcp4Connection_addOutStreamSegment(hlf->count_new, &nids_last_pcap_header->ts);
	}
	close(fd);
      }
      /* set lastTime for stream */
      Tcp4Connection_setOutStreamLastTime(&(nids_last_pcap_header->ts));
    }
    else { // data for client
      hlf = &a_tcp->client; // stream in
      logf("NIDS_DATA: %s (id = %u) %u bytes in", tuple4string, **id, hlf->count_new);
      /* dump data to a file */
      streamId = Tcp4Connection_getInStreamId();
      fd = open_streamfile(streamId);
      if (fd != -1) {
	res = write(fd, hlf->data, hlf->count_new);
	if (res != -1) {
	  logf("NDIS_DATA: %s (id = %u) written %u bytes to %s", tuple4string, **id, res, to_streamfile_path(streamId));
	  /* creating new InStreamSegment record, if new data is successfully written */
	  Tcp4Connection_addInStreamSegment(hlf->count_new, &nids_last_pcap_header->ts);
	}
	close(fd);
      }
      /* set lastTime for stream */
      Tcp4Connection_setInStreamLastTime(&(nids_last_pcap_header->ts));
    }

    /* finally, set lastTime for connection */
    Tcp4Connection_setLastTime(&(nids_last_pcap_header->ts));

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Tcp4Connection.object);

    return;
  }

  /* unknown connection status, but libnids is exiting, we must save the stream data in the DB */
  if (a_tcp->nids_state == NIDS_EXITING) {
    logf("NIDS_EXITING: %s (id = %u)", tuple4string, **id);

    /* save stream dump in the DB */
    streamId = Tcp4Connection_getOutStreamId();
    Tcp4Connection_setOutStreamData(to_streamfile_path(streamId));
    streamId = Tcp4Connection_getInStreamId();
    Tcp4Connection_setInStreamData(to_streamfile_path(streamId));

    /* not setting finalStatus and lastTime */

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Tcp4Connection.object);

    return;
  }

  return;
}

void udp4_callback(struct tuple4 *addr, char *buf, int len, struct ip *iph) {
  int fd, id, res;
  char tuple4string[64];

  strncpy(tuple4string, to_tuple4string(*addr), sizeof(tuple4string)); // hold it locally

  /* instantiate a new entity object or get already stored one for this tuple4 */
  Udp4Stream.object = Util_findUdp4Stream(*addr);
  if (Udp4Stream.object == NULL) {
    logf("%s object not found in database, instantiating a new one", tuple4string);
    Udp4Stream.object = Util_newUdp4Stream(*addr, &(nids_last_pcap_header->ts));
    logf("%s object successfuly instantiated (id = %u, streamId = %u)", tuple4string, Udp4Stream_getId(), Udp4Stream_getStreamId());
  } else {
    logf("%s object found in database (id = %u, streamId = %u)", tuple4string, Udp4Stream_getId(), Udp4Stream_getStreamId());
  }

  id = Udp4Stream_getStreamId();
  
  /* dump payload to file */
  fd = open_streamfile(id);
  if (fd != -1) {
    res = write(fd, buf, len);
    if (res != -1) {
      logf("%s (ip4StreamId = %u) written %u bytes to %s", tuple4string, id, res, to_streamfile_path(id));
      /* creating new StreamSegment record, if new data is successfully written */
      Udp4Stream_addStreamSegment(len, &nids_last_pcap_header->ts);
    }
    close(fd);
  }

  /* finally, set lastTime */
  Udp4Stream_setLastTime(&(nids_last_pcap_header->ts));

  // DEBUG
  // hexdump((void *) a_packet + headerlen, payloadlen);

  /* delete local references explicitly */
  (*jni)->DeleteLocalRef(jni, Udp4Stream.object);

  return;
}


int main (int argc, char *argv[]) {
  int res;
  char *classpath;
  char *pathbuf;
  struct stat statbuf;
  
  jmethodID utilMethod;
  jstring argString;

  /* process command line args */
  opterr = 0;
  if(getopt(argc, argv, "d:") != 'd') {
    usage();
  }
  if (strlen(optarg) > PATH_MAX - 63) { // don't want workdir path > PATH_MAX - 64
    die("working directory path too long");
  }

  /* get working directory, chdir() to it and see if it's writeable */
  pathbuf = (char *) malloc(PATH_MAX);
  if (getcwd(pathbuf, PATH_MAX) == NULL) { // store current directory in pathbuf
    logf("FATAL: getcwd() failed: %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
  res = chdir(optarg); // see if dir exists and is searchable
  if (res == -1) {
    logf("FATAL: cannot chdir() to supplied working directory: %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* stat() it an see if it's writable */
  res = stat(".", &statbuf);
  if (res == -1) {
    logf("FATAL: cannot stat() working directory: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (!(statbuf.st_uid == geteuid() && statbuf.st_mode & S_IWUSR) &&
      !(statbuf.st_gid == getegid() && statbuf.st_mode & S_IWGRP) &&
      !(statbuf.st_mode & S_IWOTH)) { die("working directory not writeable"); }
  /* change dir back */
  res = chdir(pathbuf);
  if (res == -1) {
    logf("FATAL: cannot chdir() back after testing working directory: %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
  free(pathbuf);
  /* set workdir */
  strncpy(workdir, optarg, PATH_MAX - 64);

  /* get and set input file, error handling is done by libnids */
  if((argc - optind) != 1) {
    usage();
  }
  strncpy(inputfile, argv[optind], PATH_MAX);

  /* get and set the class path */
  classpath = getenv("CLASSPATH");
  if (classpath == NULL) {
    die("CLASSPATH must be set");
  }
  
  /* all strings there to get started, summarize them  */
  logf("input file: %s", inputfile);
  logf("supplied working directory: %s", workdir);
  logf("CLASSPATH: %s", classpath);
  
  /* initialize libnids */
  nids_params.filename = inputfile; // file given on the command line
  nids_params.device = NULL; // no device, it's a file
  /* disable multithreading as nids_last_pcap_header is shared beetwen threads, and so correct values are not guaranteed */
  nids_params.multiproc = 0;

  if (!nids_init())
  {
    logf("nids_init() failed: %s", nids_errbuf);
    exit(1);
  }
  
  /* start the JVM */
  if (jvm_start(classpath) != JNI_OK) {
    die("failed to start the jvm");
  }
  log("jvm started");

  init_jobjectholders();
  
  /* create our pcap2sql.Util object */
  utilMethod = (*jni)->GetMethodID(jni, Util.class, "<init>", "(Ljava/lang/String;)V");
  e();
  argString = (*jni)->NewStringUTF(jni, workdir); // method argument = workdir
  e();
  Util.object = (*jni)->NewObject(jni, Util.class, utilMethod, argString);
  e();

  /* register the callback functions */
  nids_register_ip(&ip4_callback);
  nids_register_tcp(&tcp4_callback);
  nids_register_udp(&udp4_callback);

  /* the loop */
  nids_run();

  /* insert all non-TCP streams */
  while ((Ip4Stream.object = Util_iterateAllNonTcp4Streams()) != NULL) {
    Ip4Stream_setData(to_streamfile_path(Ip4Stream_getId()));

    /* delete local references explicitly */
    (*jni)->DeleteLocalRef(jni, Ip4Stream.object);
  }

  /* close the DB */
  utilMethod = (*jni)->GetMethodID(jni, Util.class, "closeDb", "()V");
  e();
  (*jni)->CallVoidMethod(jni, Util.object, utilMethod);
  e();

  /* shut down the JVM */
  if(jvm_shutdown() == JNI_OK) {
    log("jvm shut down");
  } else {
    log("failed to shut down the jvm");
  }

  log("exiting");
  exit(EXIT_SUCCESS);
}
