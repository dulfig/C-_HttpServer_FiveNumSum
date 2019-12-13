
#include	"serverHeader.h"
#include	"JSONValue.h"


int JSONValue::InputCharStream::peek(){
  while(bufCursor_ >= bufJustBeyondLast_){
    if(haveSeenEof_){
      return(EOF);
    }
    int	numChars;
    if( (numChars = read(inFd_,buffer_,BUFFER_LEN)) < 0 ){
      fprintf(stderr,"read() failed for JSON source file: %s\n",
	      strerror(errno)
	     );
      exit(EXIT_FAILURE);
    }

    haveSeenEof_	 = (numChars < BUFFER_LEN);
    bufCursor_	 = buffer_;
    bufJustBeyondLast_ = buffer_ + numChars;
  }
  return((int)*bufCursor_);
}


void JSONValue::InputCharStream::advance(){
  int c	= peek();

  if(c != EOF){
    bufCursor_++;
  }
}

JSONSyntacticElement
		JSONValue::Tokenizer::eof__(EOF);

JSONSyntacticElement
		JSONValue::Tokenizer::beginCurlyBrace__((int)'{');

JSONSyntacticElement
		JSONValue::Tokenizer::endCurlyBrace__((int)'}');

JSONSyntacticElement
		JSONValue::Tokenizer::beginSquareBracket__((int)'[');

JSONSyntacticElement
		JSONValue::Tokenizer::endSquareBracket__((int)']');

JSONSyntacticElement
		JSONValue::Tokenizer::comma__((int)',');

JSONSyntacticElement
		JSONValue::Tokenizer::colon__((int)':');

JSONValue* JSONValue::Tokenizer::scanNumber(char	firstC){

  bool		isInteger	  = true;
  bool		isNegative	  = false;
  bool		haveSeenDecimalPt = false;
  bool		haveSeenExponentE = false;
  bool		haveSeenDigit	  = false;
  long long	integer		  = 0;
  std::string		text;

  text += firstC;

  if(firstC == '-'){
    isNegative = true;
  }
  else
  if(firstC == '+'){
  }
  else
  if(isdigit(firstC) ){
    integer	= firstC - '0';
    haveSeenDigit = true;
  }
  else
  if(firstC == '.'){
    isInteger = false;
    haveSeenDecimalPt = true;
  }
  else{
    fprintf(stderr,
	    "Non-handled char '%c' passed to "
	    "JSONValue::Tokenizer::scanNumber()",
	     firstC
	    );
    exit(EXIT_FAILURE);
  }

  char subsequentC;
  bool isFinishedReading = false;

  if(isInteger){

    while(!inputStream_.isAtEnd()){
      subsequentC = inputStream_.peek();

      if(isdigit(subsequentC)){
		haveSeenDigit = true;
		integer	= (10 * integer) + (subsequentC - '0');
		text += subsequentC;
		inputStream_.advance();
      }
      else
      if(subsequentC == '.'){
		text += subsequentC;
		haveSeenDecimalPt = true;
		isInteger = false;
		inputStream_.advance();
		break;
      }
      else
      if((subsequentC == 'e')||(subsequentC == 'E')){
		text += subsequentC;
		haveSeenExponentE = true;
		isInteger = false;
		inputStream_.advance();
		break;
      }
      else
      {
	isFinishedReading = true;
	break;
      }
    }
  }

  if(!isFinishedReading)
  {
    while(!inputStream_.isAtEnd())
    {
      char prevC = subsequentC;

      subsequentC = inputStream_.peek();

      if(isdigit(subsequentC)){
		haveSeenDigit = true;
		text += subsequentC;
		inputStream_.advance();
      }
      else
      if(subsequentC == '.'){
		if(haveSeenDecimalPt || haveSeenExponentE){
		  break;
		}

		text += subsequentC;
		haveSeenDecimalPt = true;
		inputStream_.advance();
		}
      else
      if((subsequentC == 'e') || (subsequentC == 'E')){
		if(!haveSeenDigit){
		  fprintf(stderr,
			  "Missing digit(s) before exponent of JSON floating pt number"
			 );
		  exit(EXIT_FAILURE);
		}

		if(haveSeenExponentE){
		  break;
		}

		haveSeenDigit = false;
		text += subsequentC;
		haveSeenExponentE = true;
		inputStream_.advance();
		  }
      else
      if((subsequentC == '+') || (subsequentC == '-')){
		if((prevC != 'e') && (prevC != 'E')){
		  break;
		}

		text += subsequentC;
		inputStream_.advance();	  
		}
      else{
		isFinishedReading = true;
		break;
      }
    }
  }

  if(!haveSeenDigit){
    if(haveSeenExponentE){
      fprintf(stderr,
	      "Missing digit(s) in exponent of JSON floating pt number"
	     );
      exit(EXIT_FAILURE);
    }
    else{
      fprintf(stderr,"Missing digits in JSON number");
      exit(EXIT_FAILURE);
    }
  }

  return(isInteger
	  ? new JSONNumber
			(text,
			 isNegative
			  ? (long long)-integer
			  : (long long)+integer
			)
	  : new JSONNumber(text,strtod(text.c_str(),NULL))
	);
}

JSONValue* JSONValue::Tokenizer::scanString(){
  
  std::string text;
  char c;
  while(!inputStream_.isAtEnd()){
    c = inputStream_.peek();
    inputStream_.advance();
    if(c == QUOTE_CHAR){
      break;
    }
    else
    if(c == '\\'){
      if(inputStream_.isAtEnd()){
		fprintf(stderr,"Illegal escape char sequence");
		exit(EXIT_FAILURE);
      }
      c	= inputStream_.peek();
      inputStream_.advance();
      switch  (c){
      case QUOTE_CHAR :
		text += QUOTE_CHAR;
		break;
      case '\\' :
		text += '\\';
		break;
      case '/' :
		text += '/';
		break;
      case 'b' :
		text += '\b';
		break;
      case 'f' :
		text += '\f';
		break;
      case 'n' :
		text += '\n';
		break;
      case 'r' :
		text += '\r';
		break;
      case 't' :
		text += '\t';
		break;
      default :
		fprintf(stderr,"Illegal escape char sequence");
		exit(EXIT_FAILURE);
      }
    }
    else{
      text += c;
    }
  }

  if(text == "true"){
    return(new JSONTrue());
  }

  if(text == "false"){
    return(new JSONFalse());
  }

  if(text == "null"){
    return(new JSONNull());
  }

  return(new JSONString(text));
}

JSONValue* JSONValue::Tokenizer::scanner(){

  while(!inputStream_.isAtEnd()){
    char c = inputStream_.peek();

    inputStream_.advance();

    switch(c){
    case ' ' :
    case '\n' :
    case '\t' :
    case '\v' :
    case '\f' :
    case '\r' :
      continue;

    case '-' :
    case '+' :
    case '0' :
    case '1' :
    case '2' :
    case '3' :
    case '4' :
    case '5' :
    case '6' :
    case '7' :
    case '8' :
    case '9' :
      return(scanNumber(c));

    case QUOTE_CHAR :
      return(scanString());

    case '{' :
      return(&beginCurlyBrace__);

    case '}' :
      return(&endCurlyBrace__);

    case '[' :
      return(&beginSquareBracket__);

    case ']' :
      return(&endSquareBracket__);

    case ',' :
      return(&comma__);

    case ':' :
      return(&colon__);

    case '\0' :
      return(&eof__);

    default :
      fprintf(stderr,"Unexpected char '%c' (ASCII = %d) while reading JSON",
	      c,c
	     );
      exit(EXIT_FAILURE);
    }
  }

  return(&eof__);
}

JSONValue* JSONValue::parseObject(Tokenizer& tokenizer){

  JSONValue* readPtr;
  JSONObject* toReturn = new JSONObject();

  if(tokenizer.peek() == '}'){
    tokenizer.advance();
  }
  else{
    std::string	key;

    while(true){
      readPtr = parseValue(tokenizer);
      key = readPtr->getString(false);
      delete(readPtr);

      if(tokenizer.peek() != ':'){
		fprintf(stderr,"Expected ':' while reading JSON");
		exit(EXIT_FAILURE);
      }

      tokenizer.advance();

      readPtr = parseValue(tokenizer);

      toReturn->add(key,readPtr);

      if(tokenizer.peek() == ','){
		tokenizer.advance();
		continue;
      }
      else
      if(tokenizer.peek() == '}'){
		tokenizer.advance();
		break;
      }
      else{
		fprintf(stderr,"Expected '}' or ',' while reading JSON object");
		exit(EXIT_FAILURE);
      }
    }
  }
  return(toReturn);
}

JSONValue* JSONValue::parseArray(Tokenizer&	tokenizer){

  JSONValue* readPtr;
  JSONArray* toReturn = new JSONArray();

  if(tokenizer.peek() == ']'){
    tokenizer.advance();
  }
  else{
    while  (true){
      readPtr = parseValue(tokenizer);
      toReturn->add(readPtr);

      if(tokenizer.peek() == ','){
		tokenizer.advance();
		continue;
      }
      else
      if(tokenizer.peek() == ']'){
		tokenizer.advance();
		break;
      }
      else{
		fprintf(stderr,"Expected ']' or ',' while parsing JSON");
		exit(EXIT_FAILURE);
      }
    }
  }
  return(toReturn);
}

JSONValue* JSONValue::parseValue(Tokenizer&	tokenizer){

  JSONValue* readPtr	= tokenizer.advance();

  switch(readPtr->getType()){
  case STRING_JSON :
  case NUMBER_JSON :
  case TRUE_JSON :
  case FALSE_JSON :
  case NULL_JSON :
  case EOF :
    break;
  case '{' :
    return(parseObject(tokenizer));
  case '[' :
    return(parseArray(tokenizer));
  default :
    fprintf(stderr,"Expected JSON value");
  }

  return(readPtr);
}

JSONValue* JSONValue::factory(int fd, bool shouldCloseFd){

  Tokenizer	tokenizer(fd,shouldCloseFd);
  JSONValue* valuePtr = parseValue(tokenizer);

  return((valuePtr->getType() == EOF) ? NULL : valuePtr );
}

JSONValue::~JSONValue(){

}

const std::string JSONValue::getString(bool shouldQuoteText)
	const{
  fprintf(stderr,"Attempt to use non-string as key in JSON object");
  exit(EXIT_FAILURE);
}

const std::string JSONNumber::getString(bool shouldQuoteText)
	const{
  if(!text_.empty())
  {
    return(text_);
  }
  char text[MAX_TINY_ARRAY_LEN];
  if(isInteger_){
    snprintf(text,MAX_TINY_ARRAY_LEN,"%ld",getInteger());
  }
  else{
    snprintf(text,MAX_TINY_ARRAY_LEN,"%g",getFloat());
  }
  return(std::string(text));
}

const std::string JSONArray::getString(bool shouldQuoteText)
	const{
  size_t length	= array_.size();
  std::string toReturn;

  toReturn += BEGIN_JSON_ARRAY;

  for(size_t index = 0; index < length; index++){
    if(index > 0){
      toReturn	+= JSON_SEPARATOR;
    }
    toReturn += array_[index]->getString(shouldQuoteText);
  } 
  toReturn += END_JSON_ARRAY;
  return(toReturn);
}

JSONObject::~JSONObject	(){
  std::map<std::string,JSONValue*>::iterator iter = map_.begin();
  std::map<std::string,JSONValue*>::iterator end = map_.end();
  for( ; iter != end; iter++){
    delete(iter->second);
  }
}

const std::string JSONObject::getString(bool shouldQuoteText)
	const{
  bool isFirstIter = true;
  std::map<std::string,JSONValue*>::const_iterator iter	= map_.begin();
  std::map<std::string,JSONValue*>::const_iterator end	= map_.end();
  std::string toReturn;
  toReturn += BEGIN_JSON_BRACE;
  for( ; iter != end; iter++){
    if(isFirstIter){
      isFirstIter = false;
    }
    else{
      toReturn += JSON_SEPARATOR;
    }
    toReturn += QUOTE_STRING + iter->first + QUOTE_STRING;
    toReturn += JSON_MAPPER;
    toReturn += iter->second->getString(shouldQuoteText);
  } 
  toReturn += END_JSON_BRACE;
  return(toReturn);
}

void JSONObject::add(const std::string&	key, JSONValue* valuePtr){
  std::map<std::string,JSONValue*>::iterator iter = map_.find(key);
  if(iter != map_.end()){
    delete(iter->second);
    iter->second = valuePtr;
  }
  else{
    map_[key] = valuePtr;
  }
}
