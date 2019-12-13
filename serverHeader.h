
#include <stdlib.h>		// EXIT_SUCCESS et al
#include <stdio.h>		// fprintf() et al
#include <string.h>		// strlen() et al 
#include <sys/socket.h>		// For socket(), inet_ntoa()
#include <netinet/in.h>		// For sockaddr_in, htons(), inet_ntoa()
#include <arpa/inet.h>		// For inet_ntoa()
#include <netdb.h>		// For getaddrinfo()
#include <errno.h>		// For errno var
#include <sys/types.h>		// For open(), stat()
#include <sys/stat.h>		// For open(), read(), write(), stat()
#include <fcntl.h>		// and close()
#include <signal.h>
#include <wait.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>		// open(), stat(), unlink()
#include <string>
#include <list>
#include <vector>
#include <map>
#include <math.h>		// fabs()


/*----	----	----	----	----	----	----	----	----	----*
 *----									----*
 *----			Definition of constants:			----*
 *----									----*
 *----	----	----	----	----	----	----	----	----	----*/
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


//  PURPOSE:  To tell the beginning JSON brace
const char	BEGIN_JSON_BRACE	= '{';

//  PURPOSE:  To tell the ending JSON brace
const char	END_JSON_BRACE		= '{';

//  PURPOSE:  To tell the beginning JSON array
const char	BEGIN_JSON_ARRAY	= '[';

//  PURPOSE:  To tell the ending JSON array
const char	END_JSON_ARRAY		= ']';

//  PURPOSE:  To tell the JSON separator
const char	JSON_SEPARATOR		= ',';

//  PURPOSE:  To tell the JSON mapping char
const char	JSON_MAPPER		= ':';

#define		JSON_TYPE_KEY			"type"

#define		SOM_ERROR_MSG_JSON_TYPE_VALUE	"SOM error"

#define		JSON_MESSAGE_KEY		"message"
