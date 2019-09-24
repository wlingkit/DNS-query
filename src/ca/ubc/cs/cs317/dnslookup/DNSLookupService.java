package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;



public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static long startTime = 0;
    private static long endTime = 0;
    private static int numTrys = 0;

    public static DNSCache cacheInstance = DNSCache.getInstance();

    

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            System.out.println("input is " + console);
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static int resendCounter = 0;
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel){       
        System.out.println("Indirection level: " + indirectionLevel);
        
        // Base case
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        // Check cahce first
        Set<ResourceRecord> tempCache = DNSCache.getCachedResults(node);
        
        

        // 1. Call domain server with RootServer (node, rootServer)
        retrieveResultsFromServer(node, rootServer);

        //IF LOOKING FOR CANME. DO EVERYTHING THE SAME UNTIL A CNAME IS FOUND. NEED AN IF STATEMENT TO CHECK IF ITS LOOKING FOR CNAME, IF SO. BREAK WHEN CNAME FOUND
        // ONCE YOU FOUND ANOTHER IPV4, CHANGE BACK THE HOSTNAME

        // CASE TWO. NO A TYPE AND NOT AUTHORITATIVE
        if(!DNSResponse.CNAME_info.isEmpty() && DNSResponse.NS_info.isEmpty() && DNSResponse.A_info.isEmpty()){
        // CASE THREE. NO A AND NO NS. CHECK FOR CNAME
        
            System.out.println("-------------------3--------------------");
            String newHost = DNSResponse.CNAME_info.get(0).get("Rdata");
            DNSNode newNode = new DNSNode(newHost, node.getType());
            getResults(newNode, indirectionLevel+1);
        }
        
        Set<ResourceRecord> ans = new HashSet<ResourceRecord>();
        for(int i=0; i < DNSResponse.authoritativeAnswers.size(); i++){
            ResourceRecord rr_temp = toResoureRecord(node, DNSResponse.authoritativeAnswers.get(i));
            ans.add(rr_temp);
        }
        
        //just make sure you return a Set of ResourceRecords
        // cache.getCachedResults(node);
        return ans;
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server){
        byte[] encoded_message = DNSQuery.encoding(node);
        if(verboseTracing){
            FormatQueryTrace(node, server);
        }

        // Sending request
        send_message(encoded_message, server, DEFAULT_DNS_PORT);

        // Recieving answer 
        DNSResponse.clearList();
        retrieve_message(node);
        if(verboseTracing){
            FormatResponseTrace(node);
        }
        // 4b. If not, check if there are IPv4 addresses. Grab one and resend message down the path.
       
        // CASE ONE
        if(!DNSResponse.is_AA){
            // Resend with different IPv4
            if(!DNSResponse.A_info.isEmpty()){
                System.out.println("-------------------1--------------------");
                String newAddress = DNSResponse.A_info.get(resendCounter).get("Rdata");
                try{
                    InetAddress newServer = InetAddress.getByName(newAddress);
                    retrieveResultsFromServer(node, newServer);
                } catch(Exception e){
                    System.out.println(e);
                }
            } else if(!DNSResponse.NS_info.isEmpty()){
                // TODO Resolve deadend
                // Take NS
                // String newHostName = DNSResponse.NS_info.get(resendCounter).get("Rdata");
                String newHost = DNSResponse.NS_info.get(resendCounter).get("Rdata");
                DNSNode newNode = new DNSNode(newHost, node.getType());

                String newIPv4Str = resolveDEADEND(newNode, rootServer);
                DNSResponse.is_AA = false;
                    System.out.println("-------------------" + newIPv4Str + "--------------------");
                    try{
                        InetAddress newIPv4 = InetAddress.getByName(newIPv4Str);
                        retrieveResultsFromServer(node, newIPv4);
                    } catch(Exception e){
                        System.out.println(e);
                    }
            }
                        
        }
                
    }

    private static void FormatQueryTrace(DNSNode node, InetAddress server) {
        System.out.print("\n\n"); // begin with two blank lines
        RecordType qType = node.getType(); // convert type code to corresponding letter code (E.g 1 == A)
        String queryFormat = String.format("Query ID     %s %s  %s --> %s", DNSQuery.rand_id, DNSQuery.qnameStr, qType, server.getHostAddress());
        System.out.println(queryFormat);
       }

    private static void FormatResponseTrace(DNSNode node) {
        // System.out.println("Query Id     " + qs.transID + " " + qs.lookupName + "  " + convertQType + " --> " + qs.DNSIA.getHostAddress()); 
        System.out.println("Response received after " + (endTime - startTime) / 1000. + " seconds " + "(" + (numTrys) + " retries)");
        String responseFormat = String.format("Response ID: %s Authoritative = %s", DNSQuery.rand_id, DNSResponse.is_AA);
        System.out.println(responseFormat);

    
        System.out.printf("Answers [%s]\n", DNSResponse.numAnswer);
        for(int i=0; i < DNSResponse.answerRecord.size(); i++){
            ResourceRecord rrTemp = toResoureRecord(node, DNSResponse.answerRecord.get(i));
            String typeStr = DNSResponse.answerRecord.get(i).get("type");
            String qname = DNSResponse.answerRecord.get(i).get("qname");
            int typeInt = Integer.parseInt(typeStr);
            verbosePrintResourceRecord(rrTemp, typeInt, qname);
        }

        System.out.printf("Name Servers [%s]\n", DNSResponse.numNameServer);
        for(int i=0; i < DNSResponse.nameServerRecord.size(); i++){
            ResourceRecord rrTemp = toResoureRecord(node, DNSResponse.nameServerRecord.get(i));
            String typeStr = DNSResponse.nameServerRecord.get(i).get("type");
            String qname = DNSResponse.nameServerRecord.get(i).get("qname");
            int typeInt = Integer.parseInt(typeStr);
            verbosePrintResourceRecord(rrTemp, typeInt, qname);
        }

        System.out.printf("Additional Records [%s]\n", DNSResponse.numAdditionalRecord);
        for(int i=0; i < DNSResponse.additionalRecord.size(); i++){
            ResourceRecord rrTemp = toResoureRecord(node, DNSResponse.additionalRecord.get(i));
            String typeStr = DNSResponse.additionalRecord.get(i).get("type");
            String qname = DNSResponse.additionalRecord.get(i).get("qname");
            int typeInt = Integer.parseInt(typeStr);
            verbosePrintResourceRecord(rrTemp, typeInt, qname);
        }
        // resourceRecordFormat("Answers", qr);
        // resourceRecordFormat("Nameservers", qr);
        // resourceRecordFormat("Additional Information", qr);
    }
    

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype, String qname) {
        if (verboseTracing)
        //ecord.getHostName()
            System.out.format("       %-30s %-10d %-4s %s\n", qname,
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results){
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results){
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }




    // Send up message and obtaining the response
    private static void send_message(byte[] message, InetAddress server, int port){
        DatagramPacket out = new DatagramPacket(message, message.length, server, port);
        socket.connect(server, port);

        try{
            socket.send(out);
            startTime = System.currentTimeMillis();
        } catch (IOException e){
            e.printStackTrace(); 
        }
    }

    
    private static void retrieve_message(DNSNode node){
        byte[] recieve_buffer = new byte[1024];
        DatagramPacket dp = new DatagramPacket(recieve_buffer, recieve_buffer.length);
        try{
            socket.receive(dp);
            endTime = System.currentTimeMillis();
        } catch (IOException e){
            e.printStackTrace();  
            System.out.println("IOException at socket recieving");
        }
        String responseStr = ByteHelper.bytesToHex(dp.getData());

        System.out.println("Response String:");
        System.out.println(responseStr);
        DNSResponse.decoding(responseStr);
        

        // 1. Get info from the big dict
        // 2. Create ResourceRecord for each small dict
        // 3. Add each ResourceRecord into a Set<ResourceRecord>
        // Need to CACHE the results to CAHCERESULTS in DNSCACHE CLass USING ADD RESULT
        DNSCache.transferToCache(DNSResponse.A_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.AAAA_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.NS_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.CNAME_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.SOA_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.MX_info, node, cacheInstance);
        DNSCache.transferToCache(DNSResponse.OTHER_info, node, cacheInstance);
    }
    

    private static ResourceRecord toResoureRecord(DNSNode node, HashMap<String, String> record){
        cache = DNSCache.getInstance();

        // Getting hostName
        String hostName = node.getHostName();
            
        // Getting type
        String typeStr = record.get("type");
        int typeInt = Integer.parseInt(typeStr);
        RecordType type = RecordType.getByCode(typeInt);

        // Getting time-to-live
        String ttlStr = record.get("TTL");
        long ttl = Long.parseLong(ttlStr);

        // (String hostName, RecordType type, long ttl, String result)
        String RdataStr = record.get("Rdata");
        ResourceRecord rr = new ResourceRecord(hostName, type, ttl, RdataStr);
        return rr;
    }

    private static String resolveCNAME(){
        // TODO
        return "";
    }

    // Youre here becuase of a dead end
    // That means theres a NS -> A new hostname (ns1.googke.com), and will use the rootServer to start
    private static String resolveDEADEND(DNSNode node, InetAddress server){
        String newAddress = "";

        byte[] encoded_message = DNSQuery.encoding(node);
        if(verboseTracing){
            FormatQueryTrace(node, server);
        }

        // Sending request
        send_message(encoded_message, server, DEFAULT_DNS_PORT);

        // Recieving answer 
        DNSResponse.clearList();
        retrieve_message(node);
        if(verboseTracing){
            FormatResponseTrace(node);
        }
        System.out.println("*********************************************");
    // If is_AA and there's an answer. Set this to newAddress and return
        if(DNSResponse.is_AA && !DNSResponse.authoritativeAnswers.isEmpty()){
            newAddress = DNSResponse.authoritativeAnswers.get(0).get("Rdata");
            System.out.println("newAddress: " + newAddress);
            System.out.println("-------------------------------------------------------------");
            return newAddress;
        } else {
            String newTempServerStr = DNSResponse.A_info.get(0).get("Rdata");
            System.out.println("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||");
            try{
                InetAddress newTempServer = InetAddress.getByName(newTempServerStr);
                newAddress = resolveDEADEND(node, newTempServer);
                return newAddress;
            } catch(Exception e){
                System.out.println(e);
            }
            
        }
    // So either way, resend with same host name until you find an answer
    // If you get A file but none with the same qname // else if there is an ip with same host name
    // resend message with same hostname but a server from A_info
    // resend message with same hostname but a server from A_info
        return "ERROR in resolveDEADEND. Should not be here";
    }
}
