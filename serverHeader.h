
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>	
#include <netinet/in.h>	
#include <arpa/inet.h>	
#include <netdb.h>	
#include <errno.h>	
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <wait.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <math.h>	

#define		NUMERIC_AXIS_STATS_PAGE_NAME		\
		"numericAxisStats.swt"


#define		SERVER_NAME		"JoesSillyAssServer"
#define		SERVER_VERSION		"1.0"
#define		IMPLICIT_INDEX_URL	"/"
#define		EXPLICIT_INDEX_URL	"/index.html"
#define		DEFAULT_MIME_FORMAT	"text/html"
#define		SIMPLE_WEB_TEMPLATE_EXT	".swt"
#define		COOKIE_HEADER_TEXT	"Cookie:"
#define		SESSION_COOKIE_NAME	"session"
#define		BEGIN_TEMPLATE_VAR	"<$"
#define		END_TEMPLATE_VAR	"$>"
#define		NAME_VAR		"session.name"
#define		ID_VAR			"session.id"
#define		CONTENT_VAR		"session.content"
#define		R_MACHINE		"127.0.0.1"

const int	OS_CLIENT_QUEUE_LEN	= 8;
const int	FILE_BUFFER_LEN		= 64 * 1024;
const int	LINE_BUFFER_LEN		= 4096;
const int	SMALL_BUFFER_LEN	= 64;
const int	DEFAULT_PORT_NUM	= 20001;
const int	MIN_PORT_NUM		= 1024;
const int	MAX_PORT_NUM		= 65535;
const int	NEW_CLIENT_BUFFER_LEN	= 64;
const int	NUM_CLIENT_HANDLING_THREADS
					= 16;
const int	MAX_TINY_ARRAY_LEN	= 256;
const char	QUOTE_CHAR			= 0x22;

#define		QUOTE_STRING			"\""


const char	BEGIN_JSON_BRACE	= '{';

const char	END_JSON_BRACE		= '{';

const char	BEGIN_JSON_ARRAY	= '[';

const char	END_JSON_ARRAY		= ']';

const char	JSON_SEPARATOR		= ',';

const char	JSON_MAPPER		= ':';

#define		JSON_TYPE_KEY			"type"

#define		SOM_ERROR_MSG_JSON_TYPE_VALUE	"SOM error"

#define		JSON_MESSAGE_KEY		"message"
