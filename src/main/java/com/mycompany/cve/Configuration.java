package com.mycompany.cve;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper; // version 2.11.1
import com.fasterxml.jackson.annotation.JsonProperty; // version 2.11.1
import java.util.ArrayList;
import java.util.*;

public class Configuration{
    public ArrayList<Node> nodes;
}

@JsonIgnoreProperties(ignoreUnknown = true)
class CpeMatch{
    public boolean vulnerable;
    public String criteria;
    public String matchCriteriaId;
    public String versionEndIncluding;
    //public String versionEndExcluding;
}

@JsonIgnoreProperties(ignoreUnknown = true)
 class Cve{
    public String id;
    public String sourceIdentifier;
    public Date published;
    public Date lastModified;
    public String vulnStatus;
    public ArrayList<Description> descriptions;
    public Metrics metrics;
    public ArrayList<Weakness> weaknesses;
    public ArrayList<Configuration> configurations;
    public ArrayList<Reference> references;
    public String evaluatorSolution;
    public String evaluatorImpact;
}

 class CvssData{
    public String version;
    public String vectorString;
    public String accessVector;
    public String accessComplexity;
    public String authentication;
    public String confidentialityImpact;
    public String integrityImpact;
    public String availabilityImpact;
    public double baseScore;
}

 class CvssMetricV2{
    public String source;
    public String type;
    public CvssData cvssData;
    public String baseSeverity;
    public double exploitabilityScore;
    public double impactScore;
    public boolean acInsufInfo;
    public boolean obtainAllPrivilege;
    public boolean obtainUserPrivilege;
    public boolean obtainOtherPrivilege;
    public boolean userInteractionRequired;
}

 class Description{
    public String lang;
    public String value;
}

 class Description2{
    public String lang;
    public String value;
}

 class Metrics{
    public ArrayList<CvssMetricV2> cvssMetricV2;
}

 class Node{
    public String operator;
    public boolean negate;
    public ArrayList<CpeMatch> cpeMatch;
}

 class Reference{
    public String url;
    public String source;
    public ArrayList<String> tags;
}

 class Root{
    public int resultsPerPage;
    public int startIndex;
    public int totalResults;
    public String format;
    public String version;
    public Date timestamp;
    public ArrayList<Vulnerability> vulnerabilities;
}

class Vulnerability{
    public Cve cve;
        @Override
        public String toString() {
        return cve.id; // veya başka bir özelliği seçebilirsiniz
        }
}

 class Weakness{
    public String source;
    public String type;
    public ArrayList<Description> description;
}




