#!/usr/bin/env groovy
// Parse a CSV file (as exported from Vulcan) and group all the CWE
// CSV format: CWE, Title, Vuln. Instances, Vuln. Instances, SLA Status

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory
import java.util.regex.*

if (args.length != 1) {
    System.err.println "Usage: vulcan-cwe.groovy file.csv"
    System.exit(1)
}

def findPathToRoot(docs, xpath, cweIds) {
    def paths = []
    def minIndex = 0

    if (cweIds.size() > 0) {
        for (cweId:cweIds) {
            paths[paths.size()] = []
            def map = [:]
            getRelationships(map, docs[1000], xpath, 1000, cweId)
            if (map.isEmpty()) {
                getRelationships(map, docs[699], xpath, 699, cweId)
            }
            getPathsToRoot(paths, paths.size() - 1, map, cweId)
        }

        // select the shortest path to Root
        for (i = 0; i < paths.size(); i++) {
            if ((paths[i].size() > 0) && (paths[i].size() < paths[minIndex].size())) {
                minIndex = i
            }
        }

        Collections.reverse(paths[minIndex])

        if (paths[minIndex].size() == 0) {
            // No CWE found in either Views
            paths[minIndex] << cweIds[0]
        }
    }
    return paths[minIndex]
}

def getPathsToRoot(paths, index, map, current) {
    if (map.containsKey(current)) {
        if (map[current].size() == 0) {
            // We've hit the top-level
            paths[index] << current

            for (k : map.keySet()) {
                if (map[k].size() > 0) {
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

def getCweName(docs, xpath, id) {
    org.w3c.dom.NodeList nl = xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/@Name", docs[1000], XPathConstants.NODESET)
    if (nl.getLength() == 1) {
        return nl.item(0).getValue()
    } else {
        org.w3c.dom.NodeList nl2 = xpath.evaluate("/Weakness_Catalog/Categories/Category[@ID='$id']/@Name", docs[699], XPathConstants.NODESET)
        if (nl2.getLength() == 1) {
            return nl2.item(0).getValue()
        } else {
            return ''
        }
    }
}

def getRelationships(map, doc, xpath, view, id) {
    // Check if $id is a top-level CWE for this view
    def rootXPath = (view == 1000) ?
        "/Weakness_Catalog/Weaknesses/Weakness[@ID='$id' and not(Related_Weaknesses)]"
        :
        "/Weakness_Catalog/Views/View[@ID='$view']/Members/Has_Member[@CWE_ID='$id' and @View_ID='$view']"

    def xPath = (view == 1000) ?
        "/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/Related_Weaknesses/Related_Weakness[@Nature='ChildOf' and @View_ID='$view']/@CWE_ID"
        :
        "/Weakness_Catalog/Categories/Category/Relationships/Has_Member[@CWE_ID='$id' and @View_ID='$view']/@ID"

    org.w3c.dom.NodeList nl = xpath.evaluate(rootXPath, doc, XPathConstants.NODESET)
    if (nl.getLength() == 1) {
        if (!map.containsKey(id)) {
            map[id] = []
        }
    } else {
        xpath.evaluate(xPath, doc, XPathConstants.NODESET)
        .each {
            if (map[id] == null) {
                    map[id] = []
            }
            map[id] << Integer.parseInt(it.getValue())
            getRelationships(map, doc, xpath, view, Integer.parseInt(it.getValue()))
        }
    }
}

def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()

def docs = [:]
docs[699] = builder.parse(new File('cwe-699-v4.11.xml')).documentElement
docs[1000] = builder.parse(new File('cwe-1000-v4.11.xml')).documentElement

def cwePattern = Pattern.compile('CWE-([0-9]+)')

def all = [:]
Scanner scnr = new Scanner(new File(args[0]))

while (scnr.hasNextLine()) {
    def cols = scnr.nextLine().split(',')
    def matcher = cwePattern.matcher(cols[0])
    if (matcher.find()) {
        def key = Integer.parseInt(matcher.group(1))
        def previous = all[key] ? all[key] : 0
        all [ key ] = previous + Integer.parseInt(cols[2])
    }
}

print ", "
all.each {
    print "\"CWE-$it.key\", "
}
println ""
def aggregate = [:]
all.each {
    def paths = findPathToRoot(docs, xpath, [it.key])
    //def root = paths[0]
    def root = (paths.size() > 1) ? paths[1] : paths[0]
    if (!aggregate[root]) {
        aggregate[root]= []
    } 
    aggregate[root] << [it.key,it.value]
}


aggregate.each {
    print "\"CWE-${it.key}: ${getCweName(docs, xpath, it.key)}\""
    def i=0
    for (child:all.keySet()){
        print ','
        if ((aggregate[it.key][i]) && (child == aggregate[it.key][i][0])) {
            print  aggregate[it.key][i][1]
            i++
        }
    }
    println ""
    //, ${getCweName(docs, xpath, it.key)}, $it.value"
}
