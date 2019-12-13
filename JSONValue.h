
  typedef enum{
		  STRING_JSON,
		  NUMBER_JSON,
		  TRUE_JSON,
		  FALSE_JSON,
		  NULL_JSON,
		  ARRAY_JSON,
		  OBJECT_JSON,

		  LO_LEGAL_JSON	= STRING_JSON,
		  HI_LEGAL_JSON	= OBJECT_JSON
		}
		json_ty;

  inline
  bool isLegalJsonType	(int json){
	  return( (json >= LO_LEGAL_JSON) &&
		  (json <= HI_LEGAL_JSON)
		);
	}

  class	JSONSyntacticElement;

  class	JSONValue
  {
    class	InputCharStream
    {
      enum{
        BUFFER_LEN = LINE_BUFFER_LEN
      };
      int inFd_;
      char buffer_[BUFFER_LEN];
      char*	bufCursor_;
      char*	bufJustBeyondLast_;
      bool shouldCloseFd_;
      bool haveSeenEof_;
      InputCharStream();
      InputCharStream(const InputCharStream&);
      InputCharStream& operator=(const InputCharStream&);

    protected :
    public :
      InputCharStream(int newInFd, bool	newShouldCloseFd = true, size_t	newStartLineNum	= 1):
			inFd_(newInFd),
			bufCursor_(buffer_),
			bufJustBeyondLast_(buffer_),
			shouldCloseFd_(newShouldCloseFd),
			haveSeenEof_(false)
			{ }
      ~InputCharStream(){
		  if(shouldCloseFd_){
			close(inFd_);
		  }
		}
      int peek();
      bool isAtEnd(){
		  return(peek() == EOF );
		}
      void advance();
    };

    class Tokenizer{
      static
      JSONSyntacticElement eof__;
      static
      JSONSyntacticElement beginCurlyBrace__;
      static
      JSONSyntacticElement endCurlyBrace__;
      static
      JSONSyntacticElement beginSquareBracket__;
      static
      JSONSyntacticElement endSquareBracket__;
      static
      JSONSyntacticElement comma__;
      static
      JSONSyntacticElement colon__;
      InputCharStream inputStream_;
      JSONValue* lastParsedPtr_;
      Tokenizer();
      Tokenizer(const Tokenizer&);
      Tokenizer& operator= (const Tokenizer&);
    protected:
      JSONValue* scanNumber(char firstC);
      JSONValue* scanString();
      JSONValue* scanner();

    public:
      Tokenizer (int newInFd, bool newShouldCloseFd	= true, size_t newStartLineNum = 1):
				inputStream_(newInFd, newShouldCloseFd, newStartLineNum),
				lastParsedPtr_(NULL)
				{ }
      ~Tokenizer()
				{ }
      int peek(){
			  if(lastParsedPtr_ == NULL)
				lastParsedPtr_ = scanner();
			  return(lastParsedPtr_->getType());
		}
      JSONValue* advance(){
			  JSONValue* toReturn = (lastParsedPtr_ == NULL)
							? scanner()
						: lastParsedPtr_;
			  lastParsedPtr_ = scanner();
			  return(toReturn);
			}
    };
  protected :
    static
    JSONValue* parseObject (Tokenizer& tokenizer);
    static
    JSONValue* parseArray(Tokenizer& tokenizer);
    static
    JSONValue* parseValue (Tokenizer& tokenizer);

  public :
    JSONValue()
			{ }
    JSONValue(const JSONValue& source)
			{ }
    JSONValue& operator= (const JSONValue& source){
		  if(this == &source){
			return(*this);
		  }
		  return(*this);
		}
    static
    JSONValue* factory (int	fd, bool shouldCloseFd);
    virtual
    ~JSONValue();
    virtual
    int	getType	()
			const
			= 0;
    virtual
    const std::string
		getString(bool shouldQuoteText	= true)
			const;
    virtual
    size_t getLength()const
			{return(0); }
    virtual
    const JSONValue* getElement(size_t i)
			const
			{return(NULL); }
    virtual
    const JSONValue* getElement (const std::string& key)
			const
			{return(NULL); }
    virtual
    long long getInteger()
			const
			{return(0); }
    virtual
    double getFloat()
			const
			{return(0.0); }
    virtual
    bool isInteger(long long& integer, double& real)
			const{
			  real	= getFloat();
			  return(false);
			}
  };
  
  class	JSONNumber : public JSONValue{
    std::string text_;
    long long integer_;
    double float_;
    bool isInteger_;
  protected :
  
  public :
    JSONNumber(std::string& newText, long long newInteger):
				JSONValue(),
				text_(newText),
				integer_(newInteger),
				float_(0.0),
				isInteger_(true)
				{ }
    JSONNumber (std::string& newText, double newFloat):
				JSONValue(),
				text_(newText),
				integer_(0),
				float_(newFloat),
				isInteger_(false)
				{ }
    JSONNumber (long long newInteger):
				JSONValue(),
				text_(),
				integer_(newInteger),
				float_(0.0),
				isInteger_(true)
				{ }
    JSONNumber (double newFloat):
				JSONValue(),
				text_(),
				integer_(0),
				float_(newFloat),
				isInteger_(false)
				{ }
    int getType()
			const
			{return(NUMBER_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
			const;
    long long getInteger()
			const
			{return(integer_); }
    double getFloat()
			const
			{return(float_); }
    bool isInteger(long long& integer, double& real)
			const{
			  if(isInteger_){
				integer	= getInteger();
				return(true);
			  }
			  real = getFloat();
			  return(false);
			}
  };

  class	JSONString : public JSONValue{
    std::string text_;
  protected:
 
  public:
    JSONString(const std::string& newText):
				JSONValue(),
				text_(newText)
				{ }
    JSONString(const char* newTextCPtr):
				JSONValue(),
				text_(newTextCPtr)
				{ }
    int getType()
			const
			{return(STRING_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
				const{
				  return(shouldQuoteText
					  ?(QUOTE_STRING + text_ + QUOTE_STRING)
				  	  :text_
					);
				}
  };
  class	JSONTrue : public JSONValue{
  protected:

  public:
    JSONTrue():
			JSONValue()
			{ }
    int getType()
			const
			{return(TRUE_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
				const{
				  return( shouldQuoteText
				  	  ? std::string
					    (QUOTE_STRING "true" QUOTE_STRING)
					  : std::string("true")
					);
				}
  };
  class	JSONFalse : public JSONValue{
  protected:

  public:
    JSONFalse():
			JSONValue()
			{ }
    int getType()
			const
			{return(FALSE_JSON); }

    const std::string
		getString(bool shouldQuoteText = true)
				const{
				  return( shouldQuoteText
				  	  ? std::string
					    (QUOTE_STRING "false" QUOTE_STRING)
					  : std::string("false")
					);
				}
  };
  class	JSONNull : public JSONValue{
  protected:
  
  public:
    JSONNull():
			JSONValue()
			{ }
    int getType()
			const
			{return(NULL_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
				const{
				  return( shouldQuoteText
				  	  ? std::string
					    (QUOTE_STRING "null" QUOTE_STRING)
					  : std::string("null")
					);
				}
  };
  class	JSONArray : public JSONValue{
    std::vector<JSONValue*>	array_;
  protected:

  public:
    JSONArray():
			JSONValue()
			{ }
    ~JSONArray(){
	  size_t limit = array_.size();

	  for(size_t i = 0; i < limit; i++){
		delete(array_[i]);
	  }
	}
    int getType()
			const
			{return(ARRAY_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
			const;
    size_t getLength()
			const
			{return(array_.size()); }
    const JSONValue* getElement(size_t i)
			const{
			  return((i >= getLength())
				  ? NULL
				  : array_[i]
				);
			}
    void add (JSONValue* jsonElePtr){
			  array_.push_back(jsonElePtr);
			}

  };
  class	JSONObject : public JSONValue{
    std::map<std::string,JSONValue*>
				map_;
  protected:

  public:
    JSONObject():
			JSONValue()
			{ }
    ~JSONObject();
    int getType()
			const
			{return(OBJECT_JSON); }
    const std::string
		getString(bool shouldQuoteText = true)
			const;
    const JSONValue* getElement(const std::string& key)
			const{
			  std::map<std::string,JSONValue*>::
				const_iterator	iter = map_.find(key);

			  return((iter == map_.end())
				  ? NULL
				  : iter->second
				);
			}
    void add(const std::string&	key, JSONValue* valuePtr);
  };
  class	JSONSyntacticElement : public JSONValue{
    int syntacticElement_;
  protected:

  public:
    JSONSyntacticElement(int newSyntacticElement):
			JSONValue(),
			syntacticElement_(newSyntacticElement)
			{ }
    int getType()
			const
			{return(syntacticElement_); }
  };
