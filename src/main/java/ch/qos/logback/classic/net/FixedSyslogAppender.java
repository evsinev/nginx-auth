package ch.qos.logback.classic.net;

public class FixedSyslogAppender extends SyslogAppender {
    @Override
    String getPrefixPattern() {
        return "%syslogStart{" + getFacility() + "}%nopex{}";
    }
}
