package com.payneteasy.nginxauth.util;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public class VelocityBuilder {

    public VelocityBuilder() {
        Properties p = new Properties();
        p.setProperty("resource.loaders", "class");
        p.setProperty("resource.loader.class.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");

        theEngine = new VelocityEngine(p);

    }

    public VelocityBuilder add(String aKey, Object aValue) {
        if (aValue instanceof String) {
            theContext.put(aKey, StringUtils.escapeHtml((String) aValue));
        } else {
            theContext.put(aKey, aValue);
        }
        return this;
    }

    public void processTemplate(Class aClass, String aResource, Writer aOutput) throws IOException {
        URL url = aClass.getResource(aResource);
        if(url==null) {
            throw new IOException(String.format("Resource %s not found", aResource));
        } else {
            try {
                processTemplate(url, aOutput);
            } catch (IllegalStateException e) {
                throw new IOException(String.format("Can't find resource %s", url));
            }
        }
    }

    public void processTemplate(URL aUrl, Writer output) throws IOException {
        if(aUrl==null) throw new IllegalStateException("URL for resource is null");

        InputStreamReader in = new InputStreamReader(aUrl.openStream(), StandardCharsets.UTF_8);
        try {
            theEngine.evaluate(theContext, output, "velocity", in);
        } finally {
            in.close();
        }
    }


    private final VelocityContext theContext = new VelocityContext();
    private final VelocityEngine theEngine;
}
