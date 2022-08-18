#!/usr/bin/env groovy

@Grab('org.jsoup:jsoup:1.15.2')
import org.jsoup.Jsoup

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory

def printGraph(graph, root) {
    graph[root].each {
        print "CWE-$root > "
        printGraph(graph, it)
    }

    if (!graph.containsKey(root)){
        print "CWE-$root; "
    }
}

def findCweRoots(graph, doc, xpath, view, id) {
    xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/Related_Weaknesses/Related_Weakness[@Nature='ChildOf' and @View_ID='$view']/@CWE_ID",
        doc, XPathConstants.NODESET )
    .each {
        if (graph[id]==null) {
            graph[id] = []
        }
        graph[id] << it.getValue()
        findCweRoots(graph, doc, xpath, view, it.getValue())        
    }
}

// Parse the 1000 CWE view ("Research Concepts")
def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()
def doc = builder.parse(new File("cwe-1000-v4.8.xml")).documentElement

// Scrape H1 HTML page
org.jsoup.nodes.Document hdoc = Jsoup.connect("https://docs.hackerone.com/hackers/types-of-weaknesses.html").get()
org.jsoup.nodes.Element htable =  hdoc.select("table").get(0)
org.jsoup.select.Elements hrows = htable.select("tr")

hrows.each {
    if (it.select("td").size() > 1 ) {
        def id = it.select("td").get(0).text()

        // Some external ids are ill-formatted on the page
        if (id.startsWith("[")) {
            id = id.substring(1, id.length()-1)
        }

        def cwe = id
        def graphArray = []
        if (id.startsWith("CAPEC-")){

            // Find the equivalent CWE(s) for a given CAPEC
            def capec = id.substring(6)
            def nodes = xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[Related_Attack_Patterns/Related_Attack_Pattern[@CAPEC_ID='$capec']]/@ID",
            doc, XPathConstants.NODESET )
            def cwelist = ""
            nodes.each{ 
                if (cwelist.length()>0){
                    cwelist+= ", "
                }
                cwelist += "CWE-${it.getValue()}"
                def graph = [:]
                graph["root"]=it.getValue()
                findCweRoots(graph, doc, xpath, 1000, graph["root"])
                graphArray << graph
            }
            cwe=cwelist
        } else {
            def graph = [:]
            graph["root"]= cwe.substring(4)
            findCweRoots(graph, doc, xpath, 1000, graph["root"])
            graphArray << graph
        }

        def title = it.select("td").get(1).text()
        
        print "\"$id\", \"$title\", \"$cwe\", \""

        graphArray.each {
            printGraph(it, it["root"])
        }
       
        println "\""
    }
}
