#!/usr/bin/env groovy

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory
import java.util.regex.*

@Grab('com.opencsv:opencsv:5.8')
import com.opencsv.CSVReader

if (args.length != 2) {
    System.err.println 'Usage: capec-attack.groovy attck.csv cwe-capec.csv'
    System.exit(1)
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

def buildMapping(builder, xpath, docs, attckPattern, attck, mapping, cols) {

    cols[1].split('::').each {

        if(!it.isEmpty()){

            def matcher = attckPattern.matcher(it)
            if (matcher.find()) {
                def attckId = "t${matcher.group(1)}_${matcher.group(2).toLowerCase().replaceAll('\\W','_')}"

                if (attck[attckId]) {
                    for (cwe:cols[0].split('::')) {
                        try {
                            def cweId = Integer.parseInt(cwe)
                            if (!mapping[attckId]){
                                mapping[attckId] = new TreeSet<Integer>()
                            }
                            mapping[attckId].add(cweId)
                        } catch (NumberFormatException ignored) {
                        // NO-OP
                        }
                    }
                } else {
                    //println "NOT FOUND: $attckId   $it"
                }
            } else {
                //println "NOT MATCHED: $it"
            }
        }
    }
}

def formatCwes(docs, xpath, cwes){
    def f = ""
    for (cwe:cwes) {
        if (!f.isEmpty()) {
            f+=", "
        }
        f+="CWE-${cwe}:${getCweName(docs, xpath, cwe)}"
    //"=HYPERLINK(\"https://cwe.mitre.org/data/definitions/${id}.html\";\"${getCweName(docs, xpath, id)}\")"
    }
    f
}

def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()

def docs = [:]
//docs[699] = builder.parse(new File('cwe-699-v4.11.xml')).documentElement
docs[1000] = builder.parse(new File('cwe-1000-v4.11.xml')).documentElement

def attckPattern = Pattern.compile('TAXONOMY NAME:ATTACK:ENTRY ID:([0-9]+)\\.(?:[0-9]+):ENTRY NAME:([^:]+).*')

// Parse the list of all threats and store it in a map (key:id, value:array of cells)
CSVReader reader = new CSVReader(new FileReader(args[0]))
def attckRecord = []
header = ['id', 'title', 'CWE - Research Concepts', 'tactic', 'link', 'threat']
def attck = [:]
while ((attckRecord = reader.readNext()) != null) {
    if (attckRecord[0].startsWith('t')) {
        attck[attckRecord[0]] = attckRecord
    }
}

// Parse CAPEC VIEW 658: ATT&CK Related Patterns
reader = new CSVReader(new FileReader(args[1]))
def record = []
def mapping = [:]
while ((record = reader.readNext()) != null) {
    buildMapping( builder, xpath, docs, attckPattern, attck, mapping, record)
}

header.each {
    print "\"${it}\", "
}
println ''

attck.each {
    println "\"${it.key}\", \"${it.value[1]}\", \"${formatCwes(docs, xpath, mapping[it.key])}\", \"${it.value[2]}\", \"${it.value[3]}\", \"${it.value[4]}\""
}
