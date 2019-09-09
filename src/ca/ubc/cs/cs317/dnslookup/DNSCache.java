package ca.ubc.cs.cs317.dnslookup;

import java.util.*;
import java.util.function.BiConsumer;
import java.net.InetAddress;

/** This class handles a cache of DNS results. It is based on a map that links nodes (queries)
 * to a set of resource records (results). Cached results are only maintained for the duration
 * of the TTL (time-to-live) returned by the server, and are deleted before being returned to
 * the user.
 */
public class DNSCache {

    private static DNSCache instance = new DNSCache();

    private Map<DNSNode, Map<ResourceRecord, ResourceRecord>> cachedResults = new TreeMap<>();

    /** Singleton retrieval method. Only one instance of the DNS cache can be created. This
     * method returns the single DNS cache instance.
     *
     * @return Instance of a DNS cache.
     */
    public static DNSCache getInstance() {
        return instance;
    }

    /** Returns a set of resource records already cached for a particular query. If no results
     * are cached for the specified query, returns an empty set. Expired results are removed
     * from the cache before being returned. This method does not perform the query itself, it
     * only returns previously cached results.
     *
     * @param node DNS query (host name and record type) to obtain cached results.
     * @return A potentially empty set of resources associated to the query.
     */
    public Set<ResourceRecord> getCachedResults(DNSNode node) {
        Map<ResourceRecord, ResourceRecord> results = cachedResults.get(node);
        if (results == null)
            return Collections.emptySet();

        results.keySet().removeIf(record -> !record.isStillValid());
        return Collections.unmodifiableSet(results.keySet());
    }

    /** Adds a specific resource record to the DNS cache. If the cache already has an equivalent
     * resource record, the existing record is replaced if the new one expires after the existing
     * record, otherwise the existing record is maintained.
     *
     * @param record Resource record, possibly obtained from a DNS server, containing the result
     *               of a DNS query.
     */
    public void addResult(ResourceRecord record) {

        if (!record.isStillValid()) return;

        Map<ResourceRecord, ResourceRecord> results = cachedResults.get(record.getNode());
        if (results == null) {
            results = new HashMap<>();
            cachedResults.put(record.getNode(), results);
        }

        ResourceRecord oldRecord = results.get(record);
        if (oldRecord == null || oldRecord.expiresBefore(record))
            results.put(record, record);
    }

    /** Perform a specific action for each query and its set of cached records. This action can
     * be specified using a lambda expression or method name. Expired records are removed before
     * the action is performed.
     *
     * @param consumer Action to be performed for each query and set of records.
     */
    public void forEachNode(BiConsumer<DNSNode, Set<ResourceRecord>> consumer) {
        for (Map.Entry<DNSNode, Map<ResourceRecord, ResourceRecord>> entry : cachedResults.entrySet()) {
            entry.getValue().keySet().removeIf(record -> !record.isStillValid());
            if (!entry.getValue().keySet().isEmpty())
                consumer.accept(entry.getKey(), entry.getValue().keySet());
        }
    }

    /** Perform a specific action for each query and individual record. This action can be
     * specified using a lambda expression or method name. Expired records are removed before
     * the action is performed.
     *
     * @param consumer Action to be performed for each query and record.
     */
    public void forEachRecord(BiConsumer<DNSNode, ResourceRecord> consumer) {
        for (Map.Entry<DNSNode, Map<ResourceRecord, ResourceRecord>> entry : cachedResults.entrySet()) {
            entry.getValue().keySet().removeIf(record -> !record.isStillValid());
            entry.getValue().keySet().forEach(record -> consumer.accept(entry.getKey(), record));
        }
    }

    public static void transferToCache(List decoded_info, DNSNode node, DNSCache cacheInstance, Set<ResourceRecord> rrSet){
        String temp_str = "";
        // Iterating through a set.
        Iterator<HashMap> itr = decoded_info.iterator();

        while(itr.hasNext()){
            String hostName = node.getHostName();
            HashMap<String, String> temp_dict = itr.next();
            
            // Getting type
            String typeStr = temp_dict.get("type");
            int typeInt = Integer.parseInt(typeStr);
            RecordType type = RecordType.getByCode(typeInt);

            // Getting time-to-live
            String ttlStr = temp_dict.get("TTL");
            long ttl = Long.parseLong(ttlStr);

            // Getting result
            // Need to identify the type in order to select which type to use. (String/InetAddress)
            // If NS, String
            // If A or AAAA, InetAdress
            // if(typeInt)
            if(typeInt == 1 || typeInt == 28){
                String RdataStr = temp_dict.get("Rdata");
                try {
                    // (String hostName, RecordType type, long ttl, InetAddress result)
                    InetAddress result = InetAddress.getByName(RdataStr);
                    ResourceRecord rr = new ResourceRecord(hostName, type, ttl, result);

                    // Add rr to a set
                    rrSet.add(rr);

                    // cache results 
                    cacheInstance.addResult(rr);
                    
                } catch (Exception e) {
                    System.out.println(e);
                }
            } else {
                // (String hostName, RecordType type, long ttl, String result)
                String RdataStr = temp_dict.get("Rdata");
                ResourceRecord rr = new ResourceRecord(hostName, type, ttl, RdataStr);
                
                // Add rr to a set 
                rrSet.add(rr);

                // cache results 
                cacheInstance.addResult(rr);
            }
        }
    }
}
