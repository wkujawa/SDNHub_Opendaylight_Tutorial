package edu.uci.ics.jung.algorithms.shortestpath;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Port;

import ch.qos.logback.classic.Logger;
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

    
    public List<List<V>> getPath(V source, V target, Integer K)
    {
        Map<V,Integer> count =  new HashMap<V, Integer>();
        for(V v : g.getVertices()) {
            count.put(v, new Integer(0));
        }
        MapBinaryHeap<Path> B = new MapBinaryHeap<Path>();
        LinkedList<List<V>> P = new LinkedList<List<V>>();
        B.add(new Path(source));
        while (!B.isEmpty() && (count.get(target) < K)) {
            Path Pu = B.remove();
            V u = Pu.getTarget();
            Integer countU = count.get(u);
            count.put(u, countU+1);
            
            if (u.equals(target)) {
                P.add(Pu.getVertices());
            }
            
            if (countU <= K) {
                for (E e : g.getIncidentEdges(u)) {
                    for (V v: g.getIncidentVertices(e)) {
                        // Take only other node from edge
                        if (!v.equals(u)) {
                            // Loopless
                            if (!Pu.getVertices().contains(v)) {
                                Path Pv = new Path(Pu);
                                Pv.add(v);
                                B.add(Pv);
                            }
                        }
                    }
                }
            }
            
        }
        
        return P;
    }
    
    protected class Path implements Comparable<Path> {
        protected LinkedList<V> vertices;
        protected Integer cost;
        
        public Path(Path p) {
            vertices = new LinkedList<V>();
            vertices.addAll(p.getVertices());
            cost = p.getCost();
        }
        
        public Path(V v) {
            vertices = new LinkedList<V>();
            vertices.add(v);
            cost = 0;
        }
        
        public void add(V v) {
            vertices.add(v);
            cost++;
        }
        
        public V getTarget() {
            return vertices.getLast();
        }
        
        public List<V> getVertices() {
            return vertices;
        }
        
        public Integer getCost() {
            return cost;
        }
        
        
        
        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("Path [vertices=" );
            for (V dev : vertices) {
                builder.append(((Device)dev).getId() + ",");
            }
            builder.append("] cost="+cost);
            return builder.toString();
        }

        @Override
        public int compareTo(Path o) {
            if (cost == o.cost) {
                return 0;
            } else {
                if (cost > o.cost) {
                    return 1;
                } else {
                    return -1;
                }
            }
        }
    }
    
}
