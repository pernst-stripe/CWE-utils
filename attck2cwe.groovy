#!/usr/bin/env groovy

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory

if (args.length != 2) {
    System.err.println 'Usage: attck2cwe.groovy attck-capec.csv capec-cwe.csv'
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

def outputCsvLine (docs, xpath, capec2cwe, attckId, capecId) {
    print "${attckId}, "
    if ( (capecId>0) && capec2cwe[capecId]) {
        print "${capec2cwe[capecId].size()}, "
        print "\"${capec2cwe[capecId].join(', ')}\", "
        for (cwe: capec2cwe[capecId]) {
            print "=HYPERLINK(\"https://cwe.mitre.org/data/definitions/${cwe}.html\";\"CWE-${cwe}:${getCweName(docs, xpath, cwe)}\"), "
        }
        println ''
    } else {
        println "0,"
    }
}

def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()

def docs = [:]
//docs[699] = builder.parse(new File('cwe-699-v4.11.xml')).documentElement
docs[1000] = builder.parse(new File('cwe-1000-v4.11.xml')).documentElement

// Parse the ATT&CK to CAPEC mapping and store it in a map (key:attckId, value:capecId)
def attck2capec = [:]
Scanner scnr = new Scanner(new File(args[0]))
while (scnr.hasNextLine()) {
    def cols = scnr.nextLine().split(',')
    attck2capec[cols[0]] = Integer.parseInt(cols[1])
}

// Parse the CAPEC to CWEs mapping and store it in a map (key:capecId, value: [ cweId ] )
def capec2cwe = [:]
scnr = new Scanner(new File(args[1]))
while (scnr.hasNextLine()) {
    def cols = scnr.nextLine().split(',')
    def capecId = Integer.parseInt( cols[0] )
    capec2cwe[capecId] = [] as SortedSet
    if (cols.length == 2) {
        for (cwe : cols[1].split('::')) {
            if (!cwe.trim().empty) {
                capec2cwe[capecId].add(Integer.parseInt(cwe.trim()))
            }
        }
    }
}

// Join the 2 lists 
println "ATT&CK Id, CWE count, CWE Ids, CWE Details"
attck2capec.each {
    outputCsvLine (docs, xpath, capec2cwe, it.key, it.value)
}
