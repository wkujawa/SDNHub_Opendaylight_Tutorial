package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.shortestpath;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import edu.uci.ics.jung.algorithms.util.MapBinaryHeap;
import edu.uci.ics.jung.graph.Hypergraph;

public class DijkstraKShortestPath<V,E> {
    protected Hypergraph<V,E> g;

    /**
     * <p>Creates an instance of <code>DijkstraKShortestPath</code> for 
     * the specified graph
     * 
     * @param g     the graph on which distances will be calculated

     */
    public DijkstraKShortestPath(Hypergraph<V,E> g) {
        this.g = g;
    }

    
    public List<Path<V,E>> getPath(V source, V target, Integer K)
    {
        Map<V,Integer> count =  new HashMap<V, Integer>();
        for(V v : g.getVertices()) {
            count.put(v, new Integer(0));
        }
        MapBinaryHeap<Path<V,E>> B = new MapBinaryHeap<Path<V,E>>();
        LinkedList<Path<V,E>> P = new LinkedList<Path<V,E>>();
        B.add(new Path<V,E>(source));
        while (!B.isEmpty() && (count.get(target) < K)) {
            Path<V,E> Pu = B.remove();
            V u = Pu.getTarget();
            Integer countU = count.get(u);
            count.put(u, countU+1);
            
            if (u.equals(target)) {
                P.add(Pu);
            }
            
            if (countU <= K) {
                for (E e : g.getIncidentEdges(u)) {
                    for (V v: g.getIncidentVertices(e)) {
                        // Take only other node from edge
                        if (!v.equals(u)) {
                            // Loopless
                            if (!Pu.getVertices().contains(v)) {
                                Path<V,E> Pv = new Path<V,E>(Pu);
                                Pv.add(v,e);
                                B.add(Pv);
                            }
                        }
                    }
                }
            }
            
        }
        
        return P;
    }
}
