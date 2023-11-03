#!/usr/bin/env groovy

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory
import java.util.Collections

@Grab('com.opencsv:opencsv:5.8')
import com.opencsv.CSVReader

def findPathToRoot(doc, xpath, cweId) {
    def map = [:]
    getRelationships(map, doc, xpath, cweId)

    def paths = []
    paths[0] = []
    getPathsToRoot(paths, 0, map, cweId)

    // select the shortest path to Root
    def minIndex=0
    for (i=0; i<paths.size(); i++){
        if (paths[i].size() < paths[minIndex].size()) {
            minIndex=i;
        }
    }
    
    Collections.reverse(paths[minIndex])
    return paths[minIndex]
}

def getPathsToRoot(paths, index, map, current) {

    if (map.containsKey(current)){
        if (map[current].size() == 0){
            // We've hit the top-level
            paths[index] << current

            for ( k : map.keySet()) {
                if (map[k].size()>0) {
                    // Found a non-empty segment
                    paths[++index] = []
                    getPathsToRoot(paths, index, map, k)
                    break
                }
            }
        } else {
            paths[index] << current
            def next = map[current][0]
            map[current].removeAt(0)
            getPathsToRoot(paths, index, map, next)
        }
    }
}

def getRelationships(map, doc, xpath, id) {
    // Check if $id is a top-level CWE for this view
    org.w3c.dom.NodeList nl = xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id' and not(Related_Weaknesses)]", doc, XPathConstants.NODESET )
    if (nl.getLength() == 1) {
        if (!map.containsKey(id)) {
            map[id] = []
        }
    } else {
        xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/Related_Weaknesses/Related_Weakness[@Nature='ChildOf' and @View_ID='1000']/@CWE_ID",
            doc, XPathConstants.NODESET )
        .each {
            if (map[id]==null) {
                map[id] = []
            }
            map[id] << it.getValue()
            getRelationships(map, doc, xpath, it.getValue())
        }
    }
}

def getAllCwes(list, doc, xpath) {
    xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness/@ID", doc, XPathConstants.NODESET ).each {
        list << (it.getValue() as Integer)
    }
}

// Parse the 1000 CWE view ("Research Concepts") as XML
def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()
def doc = builder.parse(new File("cwe-1000-v4.11.xml")).documentElement

def cwes = new TreeSet()
getAllCwes(cwes, doc, xpath)

def maxDepth = 0
def graph = [:]
for (cwe:cwes) {
    def path = findPathToRoot(doc, xpath, cwe)
    graph[cwe] = path
    if (path.size() > maxDepth) {
        maxDepth = path.size()
    }
   /* if (cwe > 50) {
        break
    } */
}

println "id, depth, cwe"
for (cwe:cwes) {
    if (graph[cwe].size()>0) {
        for (d=1; d<=maxDepth; d++) {
            println "$cwe, $d, ${ (d<=graph[cwe].size()) ? graph[cwe][d-1] : graph[cwe][graph[cwe].size()-1]}"
        }
    }
}
