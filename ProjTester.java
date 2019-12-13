import java.io.*;
import java.net.*;
import java.util.regex.*;

class ProjTester{
  public static String getPage(URL url){
    String	toReturn	= "";
    InputStream	in		= null;

    try{
      in = url.openStream();
      in = new BufferedInputStream(in);
      Reader r = new InputStreamReader(in);
      int c;
      while((c = r.read()) != -1 ){
		toReturn += (char)c;
      }
    }
    catch(IOException ex){
      System.err.println(ex);
    }
    finally{
      if(in != null){
		try{
		  in.close();
		}
		catch (IOException e){
		}
      }
    }
    return(toReturn);
  }

  public static void main (String args[]){
    if(args.length < 1){
      System.err.println("Usage:\tjava ProjTester <url>\n");
      System.exit(1);
    }
    String urlString = args[0];
    try{
      String x0;
      String x1;
      String x2;
      String x3;
      String x4;
      String x5;
      String x6;
      String x7;
      BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
      QueryString query = new QueryString();

      System.out.print("x0: ");
      x0 = reader.readLine();
      System.out.print("x1: ");
      x1 = reader.readLine();
      System.out.print("x2: ");
      x2 = reader.readLine();
      System.out.print("x3: ");
      x3 = reader.readLine();
      System.out.print("x4: ");
      x4 = reader.readLine();
      System.out.print("x5: ");
      x5 = reader.readLine();
      System.out.print("x6: ");
      x6 = reader.readLine();
      System.out.print("x7: ");
      x7 = reader.readLine();

      query.add("x0",x0);
      query.add("x1",x1);
      query.add("x2",x2);
      query.add("x3",x3);
      query.add("x4",x4);
      query.add("x5",x5);
      query.add("x6",x6);
      query.add("x7",x7);

      URL url = new URL(urlString);
      String protocol= url.getProtocol();
      String host = url.getHost();
      String path = "numericAxisStats.swt";
      int port = url.getPort();

      url = new URL(protocol, host, port, path + "?" + query);
      String text = getPage(url);
      PrintWriter out = new PrintWriter("downloaded.html");

      System.out.println(urlString);
      System.out.println(text);
      out.println(text);
      out.close();
    }
    catch (MalformedURLException ex){
      System.err.println(args[0] + " is not a parseable URL");
    }
    catch (IOException ex){
      System.err.println("IOException: " + ex);
    }
  }
}
