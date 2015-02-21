package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.shortestpath;

import java.util.ArrayList;
import java.util.List;

public class Path<V,E> implements Comparable<Path<V,E>> {
    protected ArrayList<V> vertices;
    protected ArrayList<E> edges;
    protected Integer hops;
    
    public Path(Path<V,E> p) {
        vertices = new ArrayList<V>();
        edges = new ArrayList<E>();
        vertices.addAll(p.getVertices());
        edges.addAll(p.getEdges());
        hops = p.getHops();
    }
    
    public Path(V v) {
        vertices = new ArrayList<V>();
        edges = new ArrayList<E>();
        vertices.add(v);
        hops = 0;
    }
    
    public void add(V v, E e) {
        vertices.add(v);
        edges.add(e);
        hops++;
    }
    
    public V getSource() {
        return vertices.get(0);
    }
    
    public V getTarget() {
        return vertices.get(vertices.size()-1);
    }
    
    public List<V> getVertices() {
        return vertices;
    }
    
    public ArrayList<E> getEdges() {
        return edges;
    }

    public Integer getHops() {
        return hops;
    }
    
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Path [vertices=" );
        for (V v : vertices) {
            builder.append(v + ",");
        }
        builder.append("] cost="+hops);
        return builder.toString();
    }

    @Override
    public int compareTo(Path<V,E> o) {
        if (hops == o.hops) {
            return 0;
        } else {
            if (hops > o.hops) {
                return 1;
            } else {
                return -1;
            }
        }
    }
}