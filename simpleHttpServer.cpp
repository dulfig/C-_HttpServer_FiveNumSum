// http://127.0.0.1:2000/response.html?lastname=Giggle
#include "serverHeader.h"

const char QUERY_CHAR = '?';
const char FRAGMENT_CHAR = '#';
const char QUERY_ASSIGNMENT_CHAR = '=';
const char QUERY_SEGMENT_CHAR = '&';
const char QUERY_HEX_ESCAPE_CHAR = '%';
const char QUERY_SPACE_CHAR = '+';
const int COOKIE_LEN = 32;
const char* HEXADIGIT_ARRAY = "0123456789ABCDEF";
const char* DEFAULT_CONTENT_FILEPATH = "./content.txt";
const char* LOGIN_PAGE_NAME = "login";
const char* LOGOUT_PAGE_NAME = "logout";
const char* WELCOME_PAGE_NAME = "/welcome" SIMPLE_WEB_TEMPLATE_EXT;
const char* LIN_FIT_PAGE_NAME = "linFit" SIMPLE_WEB_TEMPLATE_EXT;
const char* POOR_FIT_PAGE_NAME = "poorFit" SIMPLE_WEB_TEMPLATE_EXT;
const char* ERROR_PAGE_NAME = "error" SIMPLE_WEB_TEMPLATE_EXT;
const char* USERNAME_HTML_VARNAME = "name";
const char* ID_HTML_VARNAME = "id";
const int AUTOLOGOUT_TIME_SECS = 60 * 15;
const int ASCTIME_BUFFER_LEN = 26;
const int R_PORT = 58384;
const float CORREL_THRESHOLD = 0.5;


typedef	enum{
		  BAD_HTTP_METH = -1,
		  GET_HTTP_METH,
		  PUT_HTTP_METH,
		  DELETE_HTTP_METH,
		  POST_HTTP_METH,
		  HEAD_HTTP_METH,
		  NUM_HTTP_METH
		}
		httpMethod_ty;

const char* HTTP_METHOD_NAME_ARRAY[]= {"GET", "PUT", "DELETE", "POST", "HEAD"};

typedef enum{
		  OK_HTTP_RET_CODE = 200,
		  BAD_REQUEST_HTTP_RET_CODE = 400,
		  UNAUTHORIZED_HTTP_RET_CODE = 401,
		  FORBIDDEN_HTTP_RET_CODE = 403,
		  NOT_FOUND_HTTP_RET_CODE = 404,
		  METHOD_NOT_ALLOWED_HTTP_RET_CODE = 405
		}
		httpReturnCode_ty;

#define	WITH_COOKIE_HEADER_TEMPLATE\
		"HTTP/1.0 %d %s\r\n"\
		"Server: " SERVER_NAME "/" SERVER_VERSION "\r\n"\
		"Content-Type: %s\r\n"\
		"Content-Length: %zu\r\n"\
		"Set-Cookie: %s=%s\r\n"\
		"Date: %s"\
		"\r\n"

#define WITHOUT_COOKIE_HEADER_TEMPLATE\
		"HTTP/1.0 %d %s\r\n"\
		"Server: " SERVER_NAME "/" SERVER_VERSION "\r\n"\
		"Content-Type: %s\r\n"\
		"Content-Length: %zu\r\n"\
		"Date: %s"\
		"\r\n"

#define BAD_REQUEST_PAGE\
		"<!DOCTYPE HTML>"\
		"<html lang=\"en\">"\
		" <head><title>Bad request</title></head>"\
		" <body>"\
		"  <h1>Bad request</h1>"\
		" </body>"\
		"</html>"

#define UNAUTHORIZED_PAGE\
		"<!DOCTYPE HTML>"\
		"<html lang=\"en\">"\
		" <head><title>Unauthorized</title></head>"\
		" <body>"\
		"  <h1>Unauthorized</h1>"\
		" </body>"\
		"</html>"

#define FORBIDDEN_PAGE\
		"<!DOCTYPE HTML>"\
		"<html lang=\"en\">"\
		" <head><title>Forbidden</title></head>"\
		" <body>"\
		"  <h1>Forbidden</h1>"\
		" </body>"\
		"</html>"

#define NOT_FOUND_PAGE\
		"<!DOCTYPE HTML>"\
		"<html lang=\"en\">"\
		" <head><title>Not found</title></head>"\
		" <body>"\
		"  <h1>Not found</h1>"\
		" </body>"\
		"</html>"

#define METHOD_NOT_ALLOWED_PAGE\
		"<!DOCTYPE HTML>"\
		"<html lang=\"en\">"\
		" <head><title>Method not allowed</title></head>"\
		" <body>"\
		"  <h1>Method not allowed</h1>"\
		" </body>"\
		"</html>"

#include "JSONValue.h"

const char* CACHE_CONTROL[] = {"max-age=", "s-maxage=", "public", "private", "no-cache", "no-store",};

typedef	std::map<std::string,std::string> StringToString;
typedef	std::map<std::string,std::string>::iterator StringToStringIter;

int rPort;
extern
int safeRand();
extern
const char* getMimeGuess(const char* filepathCPtr, const char* contentsCPtr);

#define	safeDelete(p){if((p)!=NULL){ delete(p); (p)=NULL;} }

#define	safeFree(p){if ((p)!=NULL){ free(p); (p)=NULL;} }

static bool shouldRun = true;
static pthread_mutex_t safeRandLock__;

class Cookie{
  char textValue_[COOKIE_LEN+1];
  
protected:

public:
	Cookie(){
	  memset(textValue_,'\0',COOKIE_LEN+1);
	}

	Cookie(unsigned int* seedPtr){
		for(size_t i = 0; i < COOKIE_LEN; i++){
			textValue_[i] =
			HEXADIGIT_ARRAY[safeRand()%16];
		  }

		textValue_[COOKIE_LEN] = '\0';
		}
		
	Cookie (const char* cPtr){
		char* destPtr = textValue_;
		char* destEndPtr = destPtr + COOKIE_LEN;

		while((*cPtr == ' ') || (*cPtr == '\t') ){
			cPtr++;
		  }
		for( ; (destPtr<destEndPtr) && isxdigit(*cPtr); destPtr++, cPtr++){
			*destPtr = *cPtr;
		  }

		for( ; destPtr <= destEndPtr; destPtr++){
			*destPtr = '\0';
		  }
		}

	Cookie(const Cookie& source){
		memcpy(textValue_,
			source.getCPtr(),
			COOKIE_LEN+1
		);
	}
	
	Cookie& operator= (const Cookie& source){
		if(this == &source){
			return(*this);
		}

		memcpy(textValue_,
			source.getCPtr(),
			COOKIE_LEN+1
		);
		return(*this);
	}

	~Cookie()
		{ }
  const char*getCPtr()
			const
			{return(textValue_); }
  bool isDefined()
			const
			{return(textValue_[0] != '\0'); }
};

class User{
  std::string name_;
  std::string id_;
  std::string content_;

protected:

public:
	User():
		name_(""),
		id_(""),
		content_("")
		{ }
	User(const std::string& name, const std::string& id, const std::string& content):
		name_(name),
		id_(id),
		content_(content)
		{ }
	User(const User& source):
		name_(source.getName()),
		id_(source.getId()),
		content_(source.getContent())
		{ }
	User& operator= (const User& source){
		if(this == &source){
			return(*this);
		}
		name_ = source.getName();
		id_ = source.getId();
		content_ = source.getContent();
		return(*this);
		}
	virtual ~User()
		{ }

	const std::string&
		getName()
			const
			{return(name_); }

	const std::string&
		getId()
			const
			{return(id_); }
	const std::string&
		getContent()
			const
			{return(content_); }
};

class SessionStore{
	class Session{
	time_t creationTime_;
    time_t lastUsedTime_;
    const User* userPtr_;
	
	protected:
    
	public:
		Session():
			creationTime_(),
			lastUsedTime_(),
			userPtr_(NULL)
			{ }
			
		Session (const User* userPtr):
			userPtr_(userPtr){
			  creationTime_ = lastUsedTime_ = time(NULL);
			}
		Session (const Session&	source):
			creationTime_(source.getCreationTime()),
			lastUsedTime_(source.getLastUsedTime()),
			userPtr_(source.getUserPtr())
			{ }
		Session& operator= (const Session& source){
			if(this == &source){
				return(*this);
			}

			creationTime_ = source.getCreationTime();
			lastUsedTime_ = source.getLastUsedTime();
			userPtr_ = source.getUserPtr();
			return(*this);
			}

		~Session()
			{}

		time_t getCreationTime()
				const
				{return(creationTime_); }
				
		time_t getLastUsedTime()
				const
				{return(lastUsedTime_); }
		const User*	getUserPtr()
				const
				{return(userPtr_); }
		void touch()
			{lastUsedTime_ = time(NULL); }

  };
  
	std::map<Cookie,Session>	cookieToSessionMap_;
	pthread_mutex_t lock_;
	SessionStore(const SessionStore&);
	SessionStore&	operator= (const SessionStore&);

protected:
	bool doesExist_NTS(const Cookie& cookie)
		const{
		  return(cookieToSessionMap_.find(cookie) != cookieToSessionMap_.end());
		}

public:
	SessionStore():
		cookieToSessionMap_(){
			pthread_mutex_init(&lock_,NULL);
		}

	~SessionStore(){
		pthread_mutex_destroy(&lock_);
	}

	Cookie createSession (unsigned int*	seedPtr, const User* userPtr){
		Cookie cookie(seedPtr);

		pthread_mutex_lock(&lock_);

		while( doesExist_NTS(cookie) ){
			cookie	= Cookie(seedPtr);
		}

		cookieToSessionMap_[cookie] = Session(userPtr);
		pthread_mutex_unlock(&lock_);
		return(cookie);
	}

	bool doesExist (const Cookie& cookie){
		bool toReturn;

		pthread_mutex_lock(&lock_);
		toReturn = doesExist_NTS(cookie);
		pthread_mutex_unlock(&lock_);

		return(toReturn);
	}

	const User* getUserPtr(const Cookie& cookie){
		const User* toReturn = NULL;

		pthread_mutex_lock(&lock_);
		std::map<Cookie,Session>::iterator iter = cookieToSessionMap_.find(cookie);

		if(iter != cookieToSessionMap_.end()){
			toReturn = iter->second.getUserPtr();
		}
		pthread_mutex_unlock(&lock_);
		return(toReturn);
	}

	bool didTouch(const Cookie&	cookie){
		bool toReturn;

		pthread_mutex_lock(&lock_);
		std::map<Cookie,Session>::iterator
		iter = cookieToSessionMap_.find(cookie);

		if(iter == cookieToSessionMap_.end()){
			toReturn = false;
		}
		else{
			toReturn = true;
			iter->second.touch();
		}
		pthread_mutex_unlock(&lock_);

		return(toReturn);
	}
	
	bool didDeleteSession(const Cookie&	cookie){
		bool toReturn = false;

		pthread_mutex_lock(&lock_);
		std::map<Cookie,Session>::iterator
		iter = cookieToSessionMap_.find(cookie);

		if(iter != cookieToSessionMap_.end()){
		cookieToSessionMap_.erase(iter);
		toReturn = true;
		}

		pthread_mutex_unlock(&lock_);
		return(toReturn);
	}

};


class UserContent{
	std::map<std::string,User> userNameToContentMap_;
	UserContent();
	UserContent(const UserContent&);
	UserContent& operator= (const UserContent&);

protected:

public:
	UserContent (const char* filepathCPtr);
	~UserContent()
		{ }
	const User*	getContentFor (const char* userNameCPtr)
		const
		{
		  std::map<std::string,User>::const_iterator iter = userNameToContentMap_.find(userNameCPtr);
		  return( (iter == userNameToContentMap_.end())
			  ? NULL
			  : &(iter->second)
			);
		}
};


class RequestHeader{
	Cookie cookie_;
  
protected:

public:
	RequestHeader() :
		cookie_()
		{ }
		
	~RequestHeader()
		{ }
		
	void setCookie(const Cookie& cookie)
		{cookie_ = cookie; }

	void clearCookie()
		{cookie_ = Cookie(); }

	const Cookie& getCookie	()
		const
			{return(cookie_); }
};


class Request{
	httpMethod_ty method_;
	char path_[LINE_BUFFER_LEN];
	char version_[SMALL_BUFFER_LEN];
	std::map<std::string,std::string> query_;
	RequestHeader header_;
	const char* contentPtr_;
	const User* userPtr_;
	bool wasCookieRecentlyDeleted_;

protected:

public:
	Request():
		method_(BAD_HTTP_METH),
		query_(),
		header_(),
		contentPtr_(NULL),
		userPtr_(NULL),
		wasCookieRecentlyDeleted_(false)
		{ }
	void initialize (int inFd, char* requestBuffer, int requestBufferLen, SessionStore& sessionStore);

  void clear(){
		method_ = BAD_HTTP_METH;
		path_[0] = '\0';
		version_[0] = '\0';
		query_.clear();
		header_.clearCookie();
		contentPtr_ = NULL;
		userPtr_ = NULL;
		wasCookieRecentlyDeleted_ = false;
	}

	~Request()
		{ }

	httpMethod_ty	getMethod()
		const
		{return(method_); }

	const char* getPath()
		const
		{return(path_); }

	const char* getVersion()
		const
		{return(version_); }

	std::map<std::string,std::string>& getQuery()
		{return(query_); }

	const std::map<std::string,std::string>& getQuery()
		const
		{return(query_); }

	const Cookie& getCookie()
		const
		{return(header_.getCookie()); }

	const char* getContentPtr()
		const
		{return(contentPtr_); }

	const User* getUserPtr()
		const
		{return(userPtr_); }

	bool getWasCookieRecentlyDeleted()
		const
		{return(wasCookieRecentlyDeleted_); }

	void setUserPtrAndCookie(const User* userPtr, const Cookie& cookie){
		userPtr_ = userPtr;
		header_.setCookie(cookie);
	}
	void clearUserPtrAndCookie(){
		userPtr_ = NULL;
		header_.clearCookie();
		wasCookieRecentlyDeleted_ = true;
	}
};


class Page{

protected:

public:
	Page()
		{ }
	virtual ~Page();
	virtual size_t getNumBytes(const Request& request) = 0;
	virtual const char* getMimeCPtr()= 0;
	virtual int write (int outFd, const Request& request) = 0;
	virtual void perhapsDispose()
		{ }
};


class FixedPage : public Page{
	size_t numBytes_;
	const char* contentsCPtr_;
	const char* mimeCPtr_;
	bool shouldDispose_;

protected:

public:
	FixedPage(const char* newContentsCPtr, const char* newMimeCPtr = DEFAULT_MIME_FORMAT):
		Page(),
		numBytes_(strlen(newContentsCPtr)),
		contentsCPtr_(newContentsCPtr),
		mimeCPtr_(newMimeCPtr),
		shouldDispose_(false)
		{ }
		
	FixedPage (size_t newNumBytes, const char* newContentsCPtr, const char* newMimeCPtr = DEFAULT_MIME_FORMAT):
		Page(),
		numBytes_(newNumBytes),
		contentsCPtr_(newContentsCPtr),
		mimeCPtr_(newMimeCPtr),
		shouldDispose_(false)
		{ }

	~FixedPage()
		{ }
	
	size_t getNumBytes(const Request& request)
		{return(numBytes_); }
		
	const char* getMimeCPtr()
		{return(mimeCPtr_); }

	int write(int outFd, const Request&	request)
		{return(::write(outFd, contentsCPtr_, getNumBytes(request))); }
		
	void perhapsDispose(){
		if  (shouldDispose_){
			delete(this);
		}
	}
};

class BaseFilePage : public Page{
	char* filepathCPtr_;
	size_t numBytes_;
	char* contentsCPtr_;
	struct timespec lastModificationTime_;

protected:
	const char* getFilepathCPtr()
		const
		{return(filepathCPtr_); }

	const char* getContentsCPtr()
		const
		{return(contentsCPtr_); }
		
	void load(struct stat& statBuffer){
		int fd	= open(filepathCPtr_,O_RDONLY);
		if(fd < 0){
			throw BAD_REQUEST_HTTP_RET_CODE;
		}
		numBytes_ = statBuffer.st_size;
		lastModificationTime_ = statBuffer.st_mtim;
		contentsCPtr_ = (char*)malloc(numBytes_+1);

		if(read(fd,contentsCPtr_,numBytes_) < 0){
			close(fd);
			throw BAD_REQUEST_HTTP_RET_CODE;
		}
		close(fd);
		contentsCPtr_[numBytes_] = '\0';
	}

public:
	BaseFilePage (const char* filepathCPtr):
		Page(),
		filepathCPtr_(strdup(filepathCPtr)),
		numBytes_(0),
		contentsCPtr_(NULL),
		lastModificationTime_(){
			struct stat statBuffer;
			if((stat(getFilepathCPtr(), &statBuffer) != 0) || !S_ISREG(statBuffer.st_mode)){
				throw BAD_REQUEST_HTTP_RET_CODE;
			}
			load(statBuffer);
		}

	~BaseFilePage(){
		safeFree(contentsCPtr_);
		safeFree(filepathCPtr_);
	}

	virtual bool getShouldSelfDispose()
		const
		{return(false); }

	size_t getNumBytes (const Request& request)
		{return(numBytes_); }

	void perhapsDispose(){
		if(getShouldSelfDispose() ){
			unlink(filepathCPtr_);
			delete(this);
		}
	}

	virtual bool didPerhapsUpdate(){
		struct stat statBuffer;

		if((stat(getFilepathCPtr(), &statBuffer) != 0) || !S_ISREG(statBuffer.st_mode)){
			throw BAD_REQUEST_HTTP_RET_CODE;
		}

		if((statBuffer.st_mtim.tv_sec < lastModificationTime_.tv_sec) 
			|| ((statBuffer.st_mtim.tv_sec  ==lastModificationTime_.tv_sec) 
			&& (statBuffer.st_mtim.tv_nsec <= lastModificationTime_.tv_nsec))
		  )
		{
				return(false);
		}

	  safeFree(contentsCPtr_);
	  load(statBuffer);
	  return(true);
	}
};

class FilePage : public BaseFilePage{
	const char* mimeCPtr_;
	bool shouldSelfDispose_;
	FilePage();
	FilePage(const FilePage&);
	FilePage& operator= (const FilePage&);  

protected:

public:
	FilePage(const char* filepathCPtr, bool shouldSelfDispose = false):
		BaseFilePage(filepathCPtr),
		mimeCPtr_
			(getMimeGuess
				(getFilepathCPtr(),
				 getContentsCPtr()
				)
			),
		shouldSelfDispose_(shouldSelfDispose)
		{ }
	~FilePage()
		{ }

	bool getShouldSelfDispose()
		const
		{return(shouldSelfDispose_); }

	const char* getMimeCPtr()
		{return(mimeCPtr_); }

	int write(int outFd, const Request&	request){
		return(::write
			(outFd,
			getContentsCPtr(),
			getNumBytes(request)
			)
		);
	}
};


class AppPage : public Page
{};

class FixedFormPage : public BaseFilePage{
	class Segment{
		Segment(const Segment&);
		Segment&	operator=	(const Segment&);

	protected:
	
	public:
    Segment()
		{ }
		
    virtual ~Segment();
	
    virtual char* memWrite(const Request& request, char* cPtr)
		const
		= 0;

    virtual size_t getLength(const Request& request)
		const
		= 0;

	};


  class TextSegment : public Segment{
    const char* textCPtr_;
    size_t length_;
    TextSegment(const TextSegment&);
    TextSegment& operator= (const TextSegment&);

  protected:

  public:
    TextSegment(const char*	textCPtr, size_t length):
		Segment(),
		textCPtr_(textCPtr),
		length_(length)
		{ }
		
    ~TextSegment()
    	{ }

    char* memWrite(const Request& request, char* cPtr)
		const{
			memcpy(cPtr,textCPtr_,length_);
			return(cPtr + length_);
		}

    size_t getLength(const Request& request)
		const
		{return(length_); }
  };

  class VarSegment : public Segment{
    std::string varName_;
    VarSegment(const VarSegment&);
    VarSegment& operator= (const VarSegment&);

  protected:
    std::string	getStringValue (const Request& request)
		const{
			if(request.getUserPtr() != NULL){
				const char* varNameCPtr	= varName_.c_str();

				if(strcmp(varNameCPtr,NAME_VAR) == 0){
				  return(request.getUserPtr()->getName());
				}

				if(strcmp(varNameCPtr,ID_VAR) == 0){
				  return(request.getUserPtr()->getId());
				}

				if(strcmp(varNameCPtr,CONTENT_VAR) == 0){
				  return(request.getUserPtr()->getContent());
				}

			}

			std::map<std::string,std::string>::const_iterator iter = request.getQuery().find(varName_);

			if(iter == request.getQuery().end()){
				return(std::string(""));
			}

			return(iter->second);
		}

  public:
	VarSegment(const std::string& varName):
		Segment(),
		varName_(varName)
		{ }
			
    ~VarSegment()
		{ }

    char* memWrite(const Request& request, char* cPtr)
		const{
			std::string	value = getStringValue(request);
			size_t length = value.length();
			memcpy(cPtr,value.c_str(),length);
			return(cPtr + length);
		}

    size_t getLength (const Request& request)
		const
		{
		  return(getStringValue(request).length());
		}
  };

	struct ContentsAndNumBytes{
		char* contentsCPtr_;
		size_t numBytes_;
		ContentsAndNumBytes(char* contentsCPtr, size_t numBytes):
			contentsCPtr_(contentsCPtr),
			numBytes_(numBytes)
			{ }

		~ContentsAndNumBytes(){
			safeFree(contentsCPtr_);
		}
	};

	std::map<pthread_t,ContentsAndNumBytes*> threadIdToPagePtrMap_;
	pthread_mutex_t pageLock_;
	std::list<Segment*> segmentPtrDS_;
	std::map<pthread_t,ContentsAndNumBytes*>::const_iterator end_;

	FixedFormPage();
  
	FixedFormPage(const FixedFormPage&);

	FixedFormPage& operator= (const FixedFormPage&);

protected:
	void clearSegmentPtrDS(){
		std::list<Segment*>::iterator iter = segmentPtrDS_.begin();
		std::list<Segment*>::iterator end = segmentPtrDS_.end();

		for( ; iter != end; iter++){
			safeDelete(*iter);
		}
		segmentPtrDS_.clear();
	}
	
	void computeSegmentPtrDS();
	
	size_t getInstantiatedLength(const Request&	request)
		const{
			size_t toReturn = 0;
			std::list<Segment*>::const_iterator iter = segmentPtrDS_.begin();
			std::list<Segment*>::const_iterator end = segmentPtrDS_.end();

			for( ; iter != end; iter++){
				toReturn += (*iter)->getLength(request);
			}

			return(toReturn);
		}

	char* getInstantiatedContent(size_t instantiatedLength, const Request& request)
		const{
			char* cPtr;
			char* instantiatedContentsCPtr = (char*)malloc(instantiatedLength+1);
			std::list<Segment*>::const_iterator iter = segmentPtrDS_.begin();
			std::list<Segment*>::const_iterator end = segmentPtrDS_.end();

			for(cPtr = instantiatedContentsCPtr; iter != end; iter++){
				cPtr = (*iter)->memWrite(request,cPtr);
			}
			*cPtr = '\0';
			return(instantiatedContentsCPtr);
		}

public:
	FixedFormPage(const char* filepathCPtr):
		BaseFilePage(filepathCPtr),
		segmentPtrDS_(),
		end_(threadIdToPagePtrMap_.end())
		{
			pthread_mutex_init(&pageLock_,NULL);
			computeSegmentPtrDS();
		}
		
	~FixedFormPage();
  
	size_t getNumBytes(const Request& request);

	const char* getMimeCPtr()
		{return(DEFAULT_MIME_FORMAT); }

	int write(int outFd, const Request& request);

	void perhapsDispose();

	bool didPerhapsUpdate(){
		if(BaseFilePage::didPerhapsUpdate()){
			pthread_mutex_lock(&pageLock_);
			computeSegmentPtrDS();
			pthread_mutex_unlock(&pageLock_);
			return(true);
		}

		return(false);
	}

};


class PageStore{
  std::map<std::string,FilePage*> uriToFilePagePtrMap_;
  std::map<std::string,FixedFormPage*> uriToFixedFormPagePtrMap_;
  FixedPage badRequestPage_;
  FixedPage unauthorizedPage_;
  FixedPage forbiddenPage_;
  FixedPage notFoundPage_;
  FixedPage methodNotAllowedPage_;


protected:
	void parseQuery(const char* sourceCPtr, std::map<std::string,std::string>& query);

	void translateUriToFilepath(const char*	uriCPtr, char* filepathSpace, size_t filepathSpaceLen,
				 std::map<std::string,std::string>& query
				);

public:
	PageStore();

	~PageStore();

	FixedPage* getBadRequestPage()
		{return(&badRequestPage_); }

	FixedPage* getUnauthorizedPage()
		{return(&unauthorizedPage_); }

	FixedPage* getForbiddenPage()
		{return(&forbiddenPage_); }

	FixedPage* getNotFoundPage	()
		{return(&notFoundPage_); }

	FixedPage* getMethodNotAllowedPage()
		{return(&methodNotAllowedPage_); }

	Page* getPagePtr(Request& request, UserContent& content, SessionStore& sessionStore);

	Page* getErrorPage(httpReturnCode_ty errCode){
		Page*	toReturn;

		switch  (errCode){
			case BAD_REQUEST_HTTP_RET_CODE :
				toReturn = getBadRequestPage();
				break;

			case UNAUTHORIZED_HTTP_RET_CODE :
				toReturn = getUnauthorizedPage();
				break;

		case FORBIDDEN_HTTP_RET_CODE :
				toReturn = getForbiddenPage();
				break;

		case METHOD_NOT_ALLOWED_HTTP_RET_CODE :
				toReturn = getMethodNotAllowedPage();
				break;

		case NOT_FOUND_HTTP_RET_CODE :
		default : 
				toReturn = getNotFoundPage();
				break;
	  }

	  return(toReturn);
	}
};

class NewClientBuffer{

	class BufferElement{
		int fd_;
		struct sockaddr_in addr_;
		socklen_t addrLen_;

  protected:

  public:
		BufferElement():
			fd_(-1),
			addr_(),
			addrLen_(sizeof(struct sockaddr_in))
			{ }

		BufferElement(int fd, const struct sockaddr_in& addr, int addrLen):
			fd_(fd),
			addr_(addr),
			addrLen_(addrLen)
			{ }

		BufferElement(const BufferElement& source):
			fd_(source.getFd()),
			addr_(source.getAddr()),
			addrLen_(source.getAddrLen())
			{ }

		BufferElement& operator= (const BufferElement& source){
		  //  I.  Application validity check:
			if  (this == &source){
				return(*this);
			}
			fd_ = source.getFd();
			addr_ = source.getAddr();
			addrLen_ = source.getAddrLen();

			return(*this);
		}
		~BufferElement()
			{ }

		int getFd()
			const
			{return(fd_); }

		const struct sockaddr_in& getAddr()
			const
			{return(addr_); }

		socklen_t getAddrLen()
			const
			{return(addrLen_); }
		void set(int fd, const struct sockaddr_in& addr, int addrLen){
			fd_ = fd;
			addr_ = addr;
			addrLen_ = addrLen;
			}

		void get(int& fd, struct sockaddr_in& addr, socklen_t& addrLen)
			const{
				fd = fd_;
				addr = addr_;
				addrLen = addrLen_;
			}
  };

	BufferElement array_[NEW_CLIENT_BUFFER_LEN];
	size_t inIndex_;
	size_t outIndex_;
	size_t count_;
	pthread_mutex_t lock_;
	pthread_cond_t notEmpty_;
  
	NewClientBuffer(const NewClientBuffer&);

	NewClientBuffer& operator= (const NewClientBuffer&);

protected:

public :
	NewClientBuffer():
		inIndex_(0),
		outIndex_(0),
		count_(0)
		{
			pthread_mutex_init(&lock_,NULL);
			pthread_cond_init(&notEmpty_,NULL);
		}

	~NewClientBuffer(){
		pthread_cond_destroy(&notEmpty_);
		pthread_mutex_destroy(&lock_);
	}

	void put(int fd, const struct sockaddr_in& addr, socklen_t addrLen){
		pthread_mutex_lock(&lock_);

		if(count_ < NEW_CLIENT_BUFFER_LEN){
			array_[inIndex_].set(fd,addr,addrLen);

			if(++inIndex_ >= NEW_CLIENT_BUFFER_LEN){
				inIndex_	= 0;
			}

			count_++;
			pthread_cond_signal(&notEmpty_);
		}
		pthread_mutex_unlock(&lock_);
	}

	void get(int& fd, struct sockaddr_in& addr, socklen_t& addrLen){
		pthread_mutex_lock(&lock_);

		while  (shouldRun && (count_ == 0)){
			pthread_cond_wait(&notEmpty_,&lock_);

			if  (!shouldRun){
				printf("Ending thread %lu\n",pthread_self());
				pthread_mutex_unlock(&lock_);
				pthread_exit(NULL);
			}

		}
		array_[outIndex_].get(fd,addr,addrLen);
		if(++outIndex_ >= NEW_CLIENT_BUFFER_LEN){
			outIndex_	= 0;
		}
		count_--;
		pthread_mutex_unlock(&lock_);
	}

	void wakeWaiters(){
		pthread_mutex_lock(&lock_);
		pthread_cond_broadcast(&notEmpty_);
		pthread_mutex_unlock(&lock_);
	}
};

class InfoForListeningThread{
  int listenFd_;
  NewClientBuffer& newClientBuffer_;
  InfoForListeningThread();
  
  InfoForListeningThread(const InfoForListeningThread&);
  
  InfoForListeningThread& operator= (const InfoForListeningThread&);

protected :

public :.
	InfoForListeningThread(int listenFd, NewClientBuffer& newClientBuffer):
		listenFd_(listenFd),
		newClientBuffer_(newClientBuffer)
		{ }

	~InfoForListeningThread()
				{ }

	int getListenFd()
		const
		{return(listenFd_); }

	NewClientBuffer& getNewClientBuffer()
		const
		{return(newClientBuffer_); }
};


class InfoForClientServingThread{
	UserContent& contentStore_;
	SessionStore& sessionStore_;
	PageStore& pageStore_;
	NewClientBuffer& newClientBuffer_;
	InfoForClientServingThread();
  
	InfoForClientServingThread(const InfoForClientServingThread&);

	InfoForClientServingThread& operator= (const InfoForClientServingThread&);

protected :

public :
	InfoForClientServingThread	(UserContent& content, SessionStore& sessionStore, PageStore& pageStore, 
		NewClientBuffer& newClientBuffer):
				contentStore_(content),
				sessionStore_(sessionStore),
				pageStore_(pageStore),
				newClientBuffer_(newClientBuffer)
				{ }

	~InfoForClientServingThread()
		{ }

	UserContent& getContentStore()
		const
		{return(contentStore_); }

	SessionStore& getSessionStore()
		const
		{return(sessionStore_); }

	PageStore& getPageStore()
		const
		{return(pageStore_); }

	NewClientBuffer& getNewClientBuffer()
		const
		{return(newClientBuffer_); }
};

int safeRand(){
	int toReturn;
	pthread_mutex_lock(&safeRandLock__);
	toReturn = rand();
	pthread_mutex_unlock(&safeRandLock__);

	return(toReturn);
}

int hexDigitValue(char hexDigit){
	if(isdigit(hexDigit) )
		return(hexDigit-'0');

	if(isupper(hexDigit) )
		return(hexDigit-'A'+10);

	return(hexDigit-'a'+10);
}

const char* firstCPtr (const char* run0, const char* run1){
	if(run0 == NULL)
		return(run1);

	if(run1 == NULL)
		return(run0);

	return((run0 < run1) ? run0 : run1 );
}

std::string	translateUrlCPtr(const char*& cPtr){
	std::string	toReturn;
	char hiNibble;
	char loNibble;
	bool shouldContinue = true;

	while(shouldContinue){
		switch(*cPtr){
			case '\0':
			case FRAGMENT_CHAR:
			case QUERY_ASSIGNMENT_CHAR:
			case QUERY_SEGMENT_CHAR:
				shouldContinue	= false;
				break;

			case QUERY_SPACE_CHAR:
				toReturn	+= ' ';
				cPtr++;
				break;

			case QUERY_HEX_ESCAPE_CHAR:
				cPtr++;	// Go past QUERY_HEX_ESCAPE_CHAR
				hiNibble	= *cPtr++;
				loNibble	= *cPtr++;

				if(!isxdigit(hiNibble) || !isxdigit(loNibble)){
					throw BAD_REQUEST_HTTP_RET_CODE;
				}

				toReturn += (char)((hexDigitValue(hiNibble) << 4) | hexDigitValue(loNibble));
				break;

			default:
				toReturn += *cPtr++;
				break;
		}

	}
	return(toReturn);
}

ssize_t rio_read(int fd, char* usrbuf, size_t n){
	ssize_t nread;
	size_t nleft = n;
	char* bufp = usrbuf;

	while(nleft > 0){
		if((nread = read(fd, bufp, nleft)) < 0){
			if (errno == EINTR){
				nread = 0;
			}
			else{
				return -1;
			}
		}
		else if(nread == 0){
			break;
		}
		nleft -= nread;
		bufp += nread;
  }

  return (n - nleft);
}

httpMethod_ty getHttpMethod(const char* methodNameCPtr){
	for(int index = 0; index < (int)NUM_HTTP_METH; index++){
		if(strcasecmp(methodNameCPtr,HTTP_METHOD_NAME_ARRAY[index]) == 0){
			return((httpMethod_ty)index);
		}
	}
  return(BAD_HTTP_METH);
}

const char*	getReturnCodeCPtr(httpReturnCode_ty	returnCode){
	const char* toReturn;

	switch(returnCode){
		case OK_HTTP_RET_CODE :
			toReturn = "OK";
			break;
		case BAD_REQUEST_HTTP_RET_CODE :
			toReturn = "Bad request";
			break;
		case UNAUTHORIZED_HTTP_RET_CODE :
			toReturn = "Unauthorized";
			break;
		case FORBIDDEN_HTTP_RET_CODE :
			toReturn = "Forbidden";
			break;
		case NOT_FOUND_HTTP_RET_CODE :
			toReturn = "Not found";
			break;
		case METHOD_NOT_ALLOWED_HTTP_RET_CODE	:
			toReturn = "Method not allowed";
			break;
	}

	return(toReturn);
}

bool beginsWith(const char* source, const char* beginning){
	size_t sourceLen = strlen(source);
	size_t beginningLen = strlen(beginning);

	if(sourceLen < beginningLen){
		return(false);
	}

	return(strncasecmp(source,beginning,beginningLen) == 0);
}

bool endsWith(const char* source, const char* ending){
	size_t sourceLen = strlen(source);
	size_t endingLen = strlen(ending);

	if(sourceLen < endingLen){
		return(false);
	}
	return(strcasecmp(source+sourceLen-endingLen,ending) == 0);
}

bool appearsToBeStaticFile(const char*	filepathCPtr){
  return( endsWith(filepathCPtr,".css") ||
	  endsWith(filepathCPtr,".csv") ||
	  endsWith(filepathCPtr,".htm") ||
	  endsWith(filepathCPtr,".html") ||
	  endsWith(filepathCPtr,".ico") ||
	  endsWith(filepathCPtr,".gif") ||
	  endsWith(filepathCPtr,".jpg") ||
	  endsWith(filepathCPtr,".jpeg") ||
	  endsWith(filepathCPtr,".png")
	);
}

const char* getMimeGuess(const char* filepathCPtr, const char* contentsCPtr){
	const char* toReturn = DEFAULT_MIME_FORMAT;

	if( endsWith(filepathCPtr,".json") ){
		toReturn = "application/json";
	}
	else
	if(endsWith(filepathCPtr,".pdf") ){
		toReturn = "application/pdf";
	}
	else
	if(endsWith(filepathCPtr,".zip") ){
		toReturn = "application/zip";
	}
	if(endsWith(filepathCPtr,".tar") ){
		toReturn = "application/x-tar";
	}
	else
	if(endsWith(filepathCPtr,".oga") ){
		toReturn = "audio/ogg";
	}
	else if(endsWith(filepathCPtr,".jpg") || endsWith(filepathCPtr,".jpeg") ||
			endsWith(filepathCPtr,".png") || endsWith(filepathCPtr,".ico")){
		if(memcmp(contentsCPtr,"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",8) == 0){
			toReturn	= "image/png";
		}
		else if((memcmp(contentsCPtr,"\x47\x49\x46\x38\x37\x61",6) == 0) ||
				(memcmp(contentsCPtr,"\x47\x49\x46\x38\x39\x61",6) == 0)){
			toReturn = "image/gif";
		}
		else if((memcmp(contentsCPtr,"\xFF\xD8\xFF\xDB",4) == 0) || (memcmp(contentsCPtr,
				"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01", 10) == 0) ||
				(memcmp(contentsCPtr,"\xFF\xD8\xFF\xEE",4) == 0) ||
				((memcmp(contentsCPtr+0,"\xFF\xD8\xFF\xE1",4) == 0)&&
				(memcmp(contentsCPtr+6,"\x45\x78\x69\x66\x00\x00",6) == 0))){
			toReturn = "image/jpeg";
		}
		else if((memcmp(contentsCPtr,"\x00\x01\x00\x00",4) == 0) ||
				(memcmp(contentsCPtr,"\x00\x00\x01\x00",4) == 0)){
			toReturn = "image/x-icon";
		}
	}
	else if(endsWith(filepathCPtr,".html") || endsWith(filepathCPtr,".htm") ){
		toReturn = DEFAULT_MIME_FORMAT;
	}
	else if(endsWith(filepathCPtr,".otf") ){
		toReturn = "font/otf";
	}
	if(endsWith(filepathCPtr,".csv") ){
		toReturn = "text/csv";
	}
	else if(endsWith(filepathCPtr,".txt") ){
		toReturn = "text/plain";
	}
	else if(endsWith(filepathCPtr,".ogv") ){
		toReturn = "video/ogg";
	}
	else{
		const char*	extensionPtr = strrchr(filepathCPtr,'.');

		if(extensionPtr == NULL){
			if(beginsWith(contentsCPtr,"<!DOCTYPE html") ||
					beginsWith(contentsCPtr,"<!DOCTYPE\thtml") ||
					beginsWith(contentsCPtr,"<html")){
				toReturn = DEFAULT_MIME_FORMAT;
			}
		}
	}
  
  return(toReturn);
}

bool operator< (const Cookie& lhs, const Cookie& rhs)
	{return( strcmp(lhs.getCPtr(),rhs.getCPtr()) < 0 ); }

UserContent::UserContent(const char* filepathCPtr):
	userNameToContentMap_(){
	FILE* filePtr= fopen(filepathCPtr,"r");

	if(filePtr == NULL){
		return;
	}

	char line[LINE_BUFFER_LEN];
	char user[LINE_BUFFER_LEN];
	char id[LINE_BUFFER_LEN];
	char content[LINE_BUFFER_LEN];
	int	lineNum	= 0;

	while(fgets(line,sizeof(line),filePtr) != NULL){
		lineNum++;

		if(sscanf(line,"%s %s \"%[^\"]s\"",user,id,content) != 3){
			fprintf(stderr,
					"Content file syntax error on line %d of %s.\n"
					"Syntax:\t<username> <id> \"content text\"",
					lineNum,filepathCPtr);
			fclose(filePtr);
			exit(EXIT_FAILURE);
		}

		userNameToContentMap_[user]	= User(user,id,content);
	}
  fclose(filePtr);
}

void Request::initialize(int inFd, char* requestBuffer, int requestBufferLen, SessionStore& sessionStore){
	char formatArray[SMALL_BUFFER_LEN];
	char tempCArray0[SMALL_BUFFER_LEN];
	char tempCArray1[SMALL_BUFFER_LEN];

	snprintf(formatArray,SMALL_BUFFER_LEN,"%%%lus %%%lus %%%lus",
		sizeof(tempCArray0)-1,sizeof(path_)-1,sizeof(version_)-1);

	if((sscanf(requestBuffer,formatArray,tempCArray0,path_,version_) < 1)  ||
			((method_ = getHttpMethod(tempCArray0)) == BAD_HTTP_METH )){
		throw BAD_REQUEST_HTTP_RET_CODE;
	}

	const char* carriageReturnCPtr;
	const char* newlineCPtr;
	const char* nextLineCPtr = requestBuffer;
	const char* requestBufferEndCPtr = requestBuffer + requestBufferLen;

	while(nextLineCPtr < requestBufferEndCPtr){
		carriageReturnCPtr = strchr(nextLineCPtr,'\r');
		newlineCPtr = strchr(nextLineCPtr,'\n');

		if((carriageReturnCPtr + 1) == newlineCPtr ){
			nextLineCPtr = newlineCPtr+1;
		}
		else if(carriageReturnCPtr == (newlineCPtr+1) ){
			nextLineCPtr = carriageReturnCPtr+1;
		}
		else if(carriageReturnCPtr == NULL){
			if(newlineCPtr == NULL){
				nextLineCPtr = NULL;
				break;
			}
			else{
				nextLineCPtr	= newlineCPtr+1;
			}
		}
		else if(newlineCPtr == NULL){
			nextLineCPtr	= carriageReturnCPtr+1;
		}
		else{
			nextLineCPtr	= firstCPtr(carriageReturnCPtr,newlineCPtr) + 1;
		}

		if((*nextLineCPtr == '\r') ||
				(*nextLineCPtr == '\n') ||
				(*nextLineCPtr == '\0')){
			break;
		}
    while((*nextLineCPtr == ' ') || (*nextLineCPtr == '\t') ){
		nextLineCPtr++;
    }
	
    if(sscanf(nextLineCPtr,"%s",tempCArray0) != 1){
		continue;
    }

    if(strncasecmp(tempCArray0, COOKIE_HEADER_TEXT, sizeof(COOKIE_HEADER_TEXT)-1) == 0){
		nextLineCPtr += sizeof(COOKIE_HEADER_TEXT)-1;
		tempCArray0[0] = '\0';
		tempCArray1[0] = '\0';

		if((sscanf(nextLineCPtr," %[^= ] = %s",tempCArray0,tempCArray1) == 2) &&
				(strcasecmp(tempCArray0,SESSION_COOKIE_NAME) == 0)){
			header_.setCookie(Cookie(tempCArray1));
			userPtr_ = sessionStore.getUserPtr(header_.getCookie());
      }
    }
  }

	if( (nextLineCPtr != NULL)  &&  (nextLineCPtr < requestBufferEndCPtr) ){
    
		while((nextLineCPtr < requestBufferEndCPtr) &&
				((*nextLineCPtr=='\r') || (*nextLineCPtr=='\n'))){
			nextLineCPtr++;
		}

		contentPtr_	= ( (*nextLineCPtr != '\0')  &&
				( nextLineCPtr  < requestBufferEndCPtr)
			)
			? nextLineCPtr
			: NULL;
	}
	else{
		contentPtr_	= NULL;
	}

}

Page::~Page()
	{ }

FixedFormPage::Segment::~Segment()
	{ }

void FixedFormPage::computeSegmentPtrDS(){
	clearSegmentPtrDS();
	const char* runCPtr;
	const char* nextVarCPtr;
	const char* endVarCPtr;

	for(runCPtr  = getContentsCPtr(); *runCPtr != '\0'; runCPtr += sizeof(END_TEMPLATE_VAR)-1){
		nextVarCPtr = strstr(runCPtr,BEGIN_TEMPLATE_VAR);

		if(nextVarCPtr == NULL){
		  break;
		}

		if(runCPtr < nextVarCPtr){
			segmentPtrDS_.push_back(new TextSegment(runCPtr,nextVarCPtr-runCPtr));
			runCPtr = nextVarCPtr;
		}

			runCPtr	+= sizeof(BEGIN_TEMPLATE_VAR)-1;
			nextVarCPtr = strstr(runCPtr,BEGIN_TEMPLATE_VAR);
			endVarCPtr = strstr(runCPtr,END_TEMPLATE_VAR);

		if((endVarCPtr == NULL) || ((nextVarCPtr != NULL)  &&  (nextVarCPtr < endVarCPtr) )){
			fprintf(stderr,"WARNING: Template %s ill-defined.\n",getFilepathCPtr());
			break;
		}

		std::string	varName;

		while(isspace(*runCPtr) ){
			runCPtr++;
		}

		while(isalnum(*runCPtr) || (*runCPtr == '_') || (*runCPtr == '.') ){
			varName	+= *runCPtr++;
		}

		while(isspace(*runCPtr) ){
			runCPtr++;
		}

		if(strncmp(runCPtr,END_TEMPLATE_VAR,sizeof(END_TEMPLATE_VAR)-1) != 0){
			fprintf(stderr,"WARNING: Template %s ill-defined.\n",getFilepathCPtr());
			break;
		}

		segmentPtrDS_.push_back(new VarSegment(varName));
	}

	if((runCPtr != NULL) && (*runCPtr != '\0') ){
		segmentPtrDS_.push_back(new TextSegment(runCPtr,strlen(runCPtr)));
	}
}

FixedFormPage::~FixedFormPage (){
	std::map<pthread_t,ContentsAndNumBytes*>::iterator iter = threadIdToPagePtrMap_.begin();
	std::map<pthread_t,ContentsAndNumBytes*>::iterator end = threadIdToPagePtrMap_.end();

	for( ; iter != end; iter++){
		safeDelete(iter->second);
	}

	clearSegmentPtrDS();
	pthread_mutex_destroy(&pageLock_);
}

size_t FixedFormPage::getNumBytes(const Request& request){
	ContentsAndNumBytes* foundDataPtr = NULL;
	pthread_t threadId = pthread_self();
	pthread_mutex_lock(&pageLock_);
	std::map<pthread_t,ContentsAndNumBytes*>::const_iterator iter = threadIdToPagePtrMap_.find(threadId);

	if(iter != end_){
		foundDataPtr = iter->second;
	}
	pthread_mutex_unlock(&pageLock_);
	if(foundDataPtr != NULL){
		return(foundDataPtr->numBytes_);
	}
	size_t numBytes = getInstantiatedLength(request);
	pthread_mutex_lock(&pageLock_);
	threadIdToPagePtrMap_[threadId] = new ContentsAndNumBytes(NULL,numBytes);
	pthread_mutex_unlock(&pageLock_);

	return(numBytes);
}

int FixedFormPage::write(int outFd, const Request& request){
	ContentsAndNumBytes* foundDataPtr = NULL;
	pthread_t threadId = pthread_self();
	pthread_mutex_lock(&pageLock_);
	std::map<pthread_t,ContentsAndNumBytes*>::const_iterator iter = threadIdToPagePtrMap_.find(threadId);

	if(iter != end_){
		foundDataPtr = iter->second;
	}
	pthread_mutex_unlock(&pageLock_);

	if((foundDataPtr != NULL)  &&  (foundDataPtr->contentsCPtr_ != NULL) ){
		FixedPage page(foundDataPtr->numBytes_,foundDataPtr->contentsCPtr_);

		return(page.write(outFd,request));
	}

	size_t numBytes = (foundDataPtr == NULL)
  				  ? getNumBytes(request)
				  : foundDataPtr->numBytes_;
	char* contentsCPtr = getInstantiatedContent(numBytes,request);
	pthread_mutex_lock(&pageLock_);

	if(foundDataPtr == NULL){
		threadIdToPagePtrMap_[threadId] = new ContentsAndNumBytes(contentsCPtr,numBytes);
	}
	else{
		foundDataPtr->contentsCPtr_ = contentsCPtr;
	}
	pthread_mutex_unlock(&pageLock_);
	FixedPage page(foundDataPtr->numBytes_,contentsCPtr);

	return(page.write(outFd,request));
}

void FixedFormPage::perhapsDispose(){
	pthread_t	threadId = pthread_self();
	pthread_mutex_lock(&pageLock_);
	std::map<pthread_t,ContentsAndNumBytes*>::iterator iter = threadIdToPagePtrMap_.find(threadId);

	if(iter != threadIdToPagePtrMap_.end()){
		safeDelete(iter->second);
		threadIdToPagePtrMap_.erase(iter);
	}
	pthread_mutex_unlock(&pageLock_);
}

void PageStore::parseQuery (const char* sourceCPtr, std::map<std::string,std::string>& query){
	while((*sourceCPtr != '\0') && (*sourceCPtr != FRAGMENT_CHAR) ){
		sourceCPtr++;
		std::string	name = translateUrlCPtr(sourceCPtr);

		if(*sourceCPtr != QUERY_ASSIGNMENT_CHAR){
			throw BAD_REQUEST_HTTP_RET_CODE;
		}
		sourceCPtr++;
		std::string	value = translateUrlCPtr(sourceCPtr);

		if  ( (*sourceCPtr != QUERY_SEGMENT_CHAR) &&
				(*sourceCPtr != FRAGMENT_CHAR) &&
				(*sourceCPtr != '\0')){
			throw BAD_REQUEST_HTTP_RET_CODE;
		}
		query[name] = value;
  }
}

void PageStore::translateUriToFilepath(const char* uriCPtr, char* filepathSpace,
				 size_t filepathSpaceLen, std::map<std::string,std::string>&query){
	const char* queryCPtr;
	const char* fragmentCPtr;
	const char* limitCPtr;

	if(strcmp(uriCPtr,IMPLICIT_INDEX_URL) == 0){
		uriCPtr	= EXPLICIT_INDEX_URL;
	}

	if(*uriCPtr == '/'){
		uriCPtr++;
	}
	queryCPtr = strchr(uriCPtr,QUERY_CHAR);
	fragmentCPtr = strchr(uriCPtr,FRAGMENT_CHAR);
	limitCPtr = firstCPtr(queryCPtr,fragmentCPtr);

	if(limitCPtr == NULL){
		strncpy(filepathSpace,uriCPtr,filepathSpaceLen);
	}
	else{
		size_t len = limitCPtr - uriCPtr;
		strncpy(filepathSpace,uriCPtr,len);
		filepathSpace[len]	= '\0';
		
		if(queryCPtr != NULL){
			parseQuery(queryCPtr,query);
		}
  }
}

PageStore::PageStore() :
				uriToFilePagePtrMap_(),
				badRequestPage_(BAD_REQUEST_PAGE),
				unauthorizedPage_(UNAUTHORIZED_PAGE),
				forbiddenPage_(FORBIDDEN_PAGE),
				notFoundPage_(NOT_FOUND_PAGE),
				methodNotAllowedPage_(METHOD_NOT_ALLOWED_PAGE)
	{ }

PageStore::~PageStore(){
	std::map<std::string,FixedFormPage*>::iterator formMapIter = uriToFixedFormPagePtrMap_.begin();
	std::map<std::string,FixedFormPage*>::iterator formMapEnd = uriToFixedFormPagePtrMap_.end();

	for( ; formMapIter != formMapEnd; formMapIter++){
		safeDelete(formMapIter->second);
	}
	std::map<std::string,FilePage*>::iterator fileMapIter = uriToFilePagePtrMap_.begin();
	std::map<std::string,FilePage*>::iterator fileMapEnd = uriToFilePagePtrMap_.end();

	for( ; fileMapIter != fileMapEnd; fileMapIter++){
		safeDelete(fileMapIter->second);
	}
}

bool isLegalNumber(const std::map<std::string,std::string>& map, const std::string&	varName, float& value){
	float temp;
	char* cPtr;
	std::map<std::string,std::string>::const_iterator iter = map.find(varName);

	if(iter == map.end())
		return(false);
	temp = strtod(iter->second.c_str(),&cPtr);

	if((*cPtr != '\0') || (cPtr == iter->second.c_str()) )
		return(false);
	value = temp;
	
	return(true);
}

bool isLegalNumber(const std::map<std::string,std::string>&map, const char* varNameCPtr, float& value){
	return(isLegalNumber(map,std::string(varNameCPtr),value) );
}

Page* PageStore::getPagePtr(Request& request, UserContent& content, SessionStore& sessionStore){
	char filePath[LINE_BUFFER_LEN];
	translateUriToFilepath(request.getPath(), filePath,sizeof(filePath), request.getQuery());
	Page* toReturn = NULL;

	if(strncmp(filePath,NUMERIC_AXIS_STATS_PAGE_NAME,strlen(NUMERIC_AXIS_STATS_PAGE_NAME)) == 0){
		std::map<std::string,std::string>::const_iterator qIter;
		float values[8];
		bool invalidValue = false;
		float x0;
		
		if(!isLegalNumber(request.getQuery(),"x0",x0) ){
			strcpy(filePath,"error.html");
		}
		else
			{ }
		float x1;
		
		if(!isLegalNumber(request.getQuery(),"x1",x1) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x2;
		
		if(!isLegalNumber(request.getQuery(),"x2",x2) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x3;
		
		if(!isLegalNumber(request.getQuery(),"x3",x3) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x4;
		
		if(!isLegalNumber(request.getQuery(),"x4",x4) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x5;
		
		if(!isLegalNumber(request.getQuery(),"x5",x5) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x6;
		
		if(!isLegalNumber(request.getQuery(),"x6",x6) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		float x7;
		
		if(!isLegalNumber(request.getQuery(),"x7",x7) ){
				strcpy(filePath,"error.html");
		}
		else
			{ }
		values[0]=x0;
		values[1]=x1;
		values[2]=x2;
		values[3]=x3;
		values[4]=x4;
		values[5]=x5;
		values[6]=x6;
		values[7]=x7;

		for(int i=0; i<8; ++i){
			if(values[i]<=0){
				invalidValue = true;
				printf("Invalid Value Entered\n");
				break;
			}
		}
		
		if(!invalidValue){	
			char sendToR [LINE_BUFFER_LEN];
			struct sockaddr_in serv_addr;
			int sockFd;
			snprintf(sendToR,LINE_BUFFER_LEN,
				"{\"type\":\"SOM request\", \"request\":\"numeric axis stats\","
				"\"id\":\"1234\",\"data sequence\": {\"type\":\"data sequence\","
				"\"name\":\"var\",  \"data type\":\"real\", \"data\":[%g,%g,%g,%g,%g,%g,%g,%g] },"
				"\"kb name\":\"My knowledge base\", \"image\": {\"type\":\"image\","
				"\"image format\":\"portable network graphic\",\"name\":\"plot.png\","
				"\"title\":\"\",  \"height in pixels\":512, \"width in pixels\":512}}",
				x0,x1,x2,x3,x4,x5,x6,x7
				);
			sockFd = socket(AF_INET, SOCK_STREAM, 0);
			
			if(sockFd < 0){
				printf("ERROR OPENING SOCKET\n");
				return NULL;
			}
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(rPort);
			
			if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){
				printf("Invalid Address\n");
				return NULL;
			}
			
			if(connect(sockFd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <0){
				printf("Connection Failed\n");
				return NULL;
			}
			send(sockFd, sendToR, strlen(sendToR), 0);			
			JSONValue* resultPtr = JSONValue::factory(sockFd, true);
			std::string test  = resultPtr->getElement("result")->getString(false);
			
			if(resultPtr->getType() != OBJECT_JSON) {
				printf("Error not a JSON Object");
                fprintf(stderr, "Not an object\n");
                throw;
            }
			JSONObject* objectPtr = (JSONObject*)resultPtr;
			
			if(resultPtr->getElement("result")->getType() != STRING_JSON || resultPtr->getElement("result")->getString(false)!="success"){
				fprintf(stderr, "Invalid result from received JSON");
				throw;
			}
			std::string mean, min, max, q25, q75, median;
            median = resultPtr->getElement("median")->getString(false);
			
			if(resultPtr->getElement("mean") != NULL){
				mean = resultPtr->getElement("mean")->getString(false);
			}
			else{
				mean = "N/A";
			}
			min = resultPtr->getElement("min")->getString(false); 
            max = resultPtr->getElement("max")->getString(false);
			q25 = resultPtr->getElement("q25")->getString(false); 
			q75 = resultPtr->getElement("q75")->getString(false);
			request.getQuery()["mean"] = mean;
			request.getQuery()["min"] = min;
			request.getQuery()["q25"] = q25;
			request.getQuery()["median"] = median;
			request.getQuery()["q75"] = q75;
			request.getQuery()["max"] = max;
			delete(resultPtr);
		}
	}
	else if(strcmp(filePath,LOGIN_PAGE_NAME) == 0){
		const char*	cPtr;
		std::map<std::string,std::string>::const_iterator varIter = request.getQuery().find(USERNAME_HTML_VARNAME);
		std::string	userName = (varIter == request.getQuery().end())
				  ? std::string("")
				  : varIter->second;
		const User*	userPtr = userName.empty()
				  ? NULL
				  : content.getContentFor(userName.c_str());
		std::string	id = ((varIter = request.getQuery().find(ID_HTML_VARNAME)) == request.getQuery().end())
				  ? std::string("")
				  : varIter->second;

		if((userPtr != NULL) && !id.empty() && (userPtr->getId() == id) ){
			cPtr = WELCOME_PAGE_NAME;
			unsigned int seed = pthread_self();
			Cookie cookie = sessionStore.createSession(&seed,userPtr);
			request.setUserPtrAndCookie(userPtr,cookie);
		}
		else{
			cPtr = EXPLICIT_INDEX_URL;
		}

		if  (*cPtr == '/'){
			cPtr++;
		}
		strcpy(filePath,cPtr);
  }
	else if(strcmp(filePath,LOGOUT_PAGE_NAME) == 0){
		const char*	cPtr;

		if(request.getUserPtr() == NULL){
			cPtr = EXPLICIT_INDEX_URL;
		}
		else{
			sessionStore.didDeleteSession(request.getCookie());
			request.clearUserPtrAndCookie();      
			cPtr = EXPLICIT_INDEX_URL;
		}

		if(*cPtr == '/'){
			cPtr++;
		}
		strcpy(filePath,cPtr);
  }

	if(appearsToBeStaticFile(filePath) ){
		FilePage* pagePtr;
		std::string uriStr = filePath;
		std::map<std::string,FilePage*>::iterator found = uriToFilePagePtrMap_.find(uriStr);

		if(found == uriToFilePagePtrMap_.end()){
			pagePtr = new FilePage(filePath);
			uriToFilePagePtrMap_[uriStr] = pagePtr;
		}
		else{
			pagePtr = found->second;
			pagePtr->didPerhapsUpdate();
		}

		toReturn = pagePtr;
	}
	else if(endsWith(filePath,SIMPLE_WEB_TEMPLATE_EXT) ){
		FixedFormPage* pagePtr;
		std::string uriStr = filePath;
		std::map<std::string,FixedFormPage*>::iterator found = uriToFixedFormPagePtrMap_.find(uriStr);

		if(found == uriToFixedFormPagePtrMap_.end()){
			pagePtr = new FixedFormPage(filePath);
			uriToFixedFormPagePtrMap_[uriStr] = pagePtr;
		}
		else{
			pagePtr = found->second;
			pagePtr->didPerhapsUpdate();
		}
		toReturn = pagePtr;
	}
	else{
		throw NOT_FOUND_HTTP_RET_CODE;
	}
	return(toReturn);
}

void showUsage (FILE* outFilePtr){
	fprintf(outFilePtr,
		"Usage:\tsimpleHttpServer <httpPort> <rPort>\n"
		"Where:\n"
		"  <httpPort> is the port to bind: int in [%d..%d], default is %d\n"
		"  <rPort> is the port for talking to R: int in [%d..%d], default is %d\n",
		MIN_PORT_NUM,MAX_PORT_NUM,DEFAULT_PORT_NUM,
		MIN_PORT_NUM,MAX_PORT_NUM,R_PORT);
}

int obtainListeningSocketFd(int port){
	int socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in socketInfo;
	memset(&socketInfo,'\0',sizeof(socketInfo));
	socketInfo.sin_family = AF_INET;
	socketInfo.sin_port = htons(port);
	socketInfo.sin_addr.s_addr = INADDR_ANY;
	int status = bind(socketDescriptor, (struct sockaddr*)&socketInfo, sizeof(socketInfo));

	if(status < 0){
		fprintf(stderr,"Could not bind to port %d\n",port);
		exit(EXIT_FAILURE);
	}
	listen(socketDescriptor,OS_CLIENT_QUEUE_LEN);
	return(socketDescriptor);
}

void writeHeader(int clientFd, httpReturnCode_ty returnCode, const Request& request, Page* pagePtr){
	char timeString[ASCTIME_BUFFER_LEN];
	const Cookie& cookie = request.getCookie();
	size_t resourceLen = pagePtr->getNumBytes(request);
	const char*	mimeCPtr = pagePtr->getMimeCPtr();
	time_t now = time(NULL);
	asctime_r(gmtime(&now),timeString);
	char header[FILE_BUFFER_LEN];
	int headerLen = (cookie.isDefined() || request.getWasCookieRecentlyDeleted())
			  ? snprintf
				(header,sizeof(header),
				 WITH_COOKIE_HEADER_TEMPLATE,
				 returnCode,getReturnCodeCPtr(returnCode),
				 mimeCPtr,
				 resourceLen,
				 SESSION_COOKIE_NAME,cookie.getCPtr(),
				 timeString
				)
			  : snprintf
				(header,sizeof(header),
				 WITHOUT_COOKIE_HEADER_TEMPLATE,
				 returnCode,getReturnCodeCPtr(returnCode),
				 mimeCPtr,
				 resourceLen,
				 timeString
				);
	write(clientFd,header,headerLen);
	printf("\n\nSending:\n");
	write(STDOUT_FILENO,header,headerLen);
}

void sigPipeHandler(int sigNum){
	fprintf(stderr,"Fine!  No input for you!\n");
}

void sigIntHandler(int sigNum){
	shouldRun	= false;
}

void* listenToServerSocket(void* vPtr){
	InfoForListeningThread* infoPtr = (InfoForListeningThread*)vPtr;
	struct sockaddr_in clientAddr;
	socklen_t clientAddrLen;
	int clientFd;
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while(shouldRun){
		clientAddrLen = sizeof(clientAddr);
		clientFd = accept
				(infoPtr->getListenFd(),
				 (sockaddr*)&clientAddr,
				 &clientAddrLen
				);

		if(clientFd < 0){
			if(shouldRun){
				perror("accept()");
			}
			break;
		}

		if(!shouldRun){
			break;
		}
		printf("accept() from host %s, port %d.\n",
			inet_ntoa(clientAddr.sin_addr),(int)ntohs(clientAddr.sin_port));
		infoPtr->getNewClientBuffer().put(clientFd,clientAddr,clientAddrLen);
	  }
	printf("listenToServerSocket() finishing\n");
	
	return(NULL);
}

void* serveClients(void* vPtr){
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	InfoForClientServingThread* infoPtr = (InfoForClientServingThread*)vPtr;
	Request request;
	fd_set originalSet;
	struct timeval time;
	struct sockaddr_in clientAddr;
	socklen_t clientAddrLen;
	int clientFd;
	time.tv_sec = AUTOLOGOUT_TIME_SECS;
	time.tv_usec = 0;

	while(shouldRun){
		char fromClient[FILE_BUFFER_LEN];
		int numBytes;
		Page* pagePtr = NULL;
		httpReturnCode_ty returnCode;
		request.clear();
		infoPtr->getNewClientBuffer().get(clientFd,clientAddr,clientAddrLen);
		FD_ZERO(&originalSet);
		FD_SET(clientFd,&originalSet);

		if(select(clientFd+1,&originalSet,NULL,NULL,&time) < 0){
			if  (errno == EINTR){
				printf("select() interrupted by signal\n");
				continue;
			}
			else{
				perror("select()");
				shouldRun = false;
				break;
			}
		}
		printf("Now serving host %s, port %d.\n",
			inet_ntoa(clientAddr.sin_addr),(int)ntohs(clientAddr.sin_port));

		if(!FD_ISSET(clientFd,&originalSet) ){
			printf("Time-out!\n");
			continue;
		}

		if((numBytes = read(clientFd,fromClient,sizeof(fromClient)-1)) < 0){
			if(!shouldRun){
				break;
		  }

			perror("read()");
			returnCode = NOT_FOUND_HTTP_RET_CODE;
			pagePtr = infoPtr->getPageStore().getErrorPage(returnCode);
			writeHeader(clientFd,returnCode,request,pagePtr);
			pagePtr->write(clientFd,request);
			pagePtr->write(STDOUT_FILENO,request);
			pagePtr->perhapsDispose();
			close(clientFd);
			continue;
		}

		fromClient[numBytes] = '\0',
		printf("Received: %d\n",numBytes);
		write(STDOUT_FILENO,fromClient,numBytes);
		write(STDOUT_FILENO,"\n\n",2);
		httpMethod_ty	method;

		try{
			request.initialize(clientFd, fromClient, numBytes, infoPtr->getSessionStore());
			pagePtr = infoPtr->getPageStore().getPagePtr(request, infoPtr->getContentStore(), infoPtr->getSessionStore());
			returnCode = OK_HTTP_RET_CODE;
			method = request.getMethod();
		}
		catch(httpReturnCode_ty	errCode){
			returnCode = errCode;
		}

		if(pagePtr == NULL){
		  pagePtr = infoPtr->getPageStore().getErrorPage(returnCode);
		}
		writeHeader(clientFd,returnCode,request,pagePtr);

		if(method != HEAD_HTTP_METH){
			pagePtr->write(clientFd,request);

			if(strstr(pagePtr->getMimeCPtr(),"text/") != NULL ){
				pagePtr->write(STDOUT_FILENO,request);
				write(STDOUT_FILENO,"\n\n",2);
			}
		}
		pagePtr->perhapsDispose();
		close(clientFd);
  }
  printf("Ending thread %lu\n",pthread_self());
  
  return(NULL);
}

int main(int argc, char* argv[]){
	int port = DEFAULT_PORT_NUM;
	const char* contentFilepathCPtr = DEFAULT_CONTENT_FILEPATH;
	rPort = R_PORT;

	switch(argc){
		case 0:
			showUsage(stderr);
			exit(EXIT_FAILURE);

		case 3:
		default :{
			char* cPtr;
			rPort = strtol(argv[2],&cPtr,0);

			if((*cPtr != '\0') || (rPort < MIN_PORT_NUM) || (rPort > MAX_PORT_NUM)){
				fprintf(stderr,"Bad R port value\n");
				showUsage(stderr);
				exit(EXIT_FAILURE);
			}
		}

		case 2:{
			char* cPtr;
			port = strtol(argv[1],&cPtr,0);

			if((*cPtr != '\0') || (port < MIN_PORT_NUM) || (port > MAX_PORT_NUM)){
				fprintf(stderr,"Bad port value\n");
				showUsage(stderr);
				exit(EXIT_FAILURE);
			}
		}
		
		case 1:
			break;
	}
	int listenFd = obtainListeningSocketFd(port);
	struct sigaction action;
	memset(&action,'\0',sizeof(action));
	action.sa_handler	= sigPipeHandler;
	sigaction(SIGPIPE,&action,NULL);
	action.sa_handler	= sigIntHandler;
	sigaction(SIGINT,&action,NULL);
	UserContent content(contentFilepathCPtr);
	SessionStore sessionStore;
	printf("Please connect to http://127.0.0.1:%d\n Press Ctrl-C to stop.\n", port);
	PageStore pageStore;
	NewClientBuffer newClientBuffer;
	pthread_mutex_init(&safeRandLock__,NULL);
	pthread_t listeningThread;
	InfoForListeningThread listenThreadInfo(listenFd,newClientBuffer);
	pthread_create(&listeningThread, NULL, listenToServerSocket, &listenThreadInfo);
	pthread_t servingThread[NUM_CLIENT_HANDLING_THREADS];
	InfoForClientServingThread	servingThreadInfo(content, sessionStore, pageStore, newClientBuffer);

	for(int i = 0; i < NUM_CLIENT_HANDLING_THREADS; i++){
		pthread_create(servingThread+i, NULL, serveClients, &servingThreadInfo);
	}
	
	while(shouldRun){
		sleep(1);
	}
	printf("Shutting down.\n");
	int toShutdownFd = socket(AF_INET,SOCK_STREAM,0);
	struct addrinfo* hostPtr;
	struct sockaddr_in serverAddr;
	getaddrinfo("localhost",NULL,NULL,&hostPtr);
	memset(&serverAddr,'\0',sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port	 = htons(port);
	serverAddr.sin_addr.s_addr = ((struct sockaddr_in*)hostPtr->ai_addr)->sin_addr.s_addr;
	connect(toShutdownFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));
	pthread_join(listeningThread,NULL);
	newClientBuffer.wakeWaiters();

	for(int i = 0; i < NUM_CLIENT_HANDLING_THREADS; i++){
		pthread_join(servingThread[i],NULL);
	}
	close(listenFd);
	pthread_mutex_destroy(&safeRandLock__);
	
	return(EXIT_SUCCESS);
}
