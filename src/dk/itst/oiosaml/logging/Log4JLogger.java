/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain
 * a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 *
 * The Initial Developer of the Original Code is Trifork A/S. Portions
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 *
 * Contributor(s):
 * Kasper Vestergaard Møller <kvm@schultz.dk>
 */
package dk.itst.oiosaml.logging;

/**
 * This class supports logging using the log4j logger.
 */
public class Log4JLogger implements Logger {
    private org.apache.log4j.Logger log;

    public Log4JLogger(String name) {
        log = org.apache.log4j.Logger.getLogger(name);
    }

    @Override
    public boolean isDebugEnabled() {
        return log.isDebugEnabled()
    }

    @Override
    public void debug(Object message) {
        log.debug(message);
    }

    @Override
    public void debug(Object message, Throwable exception) {
        log.debug(message, exception);
    }

    @Override
    public boolean isInfoEnabled() {
        return log.isInfoEnabled();
    }

    @Override
    public void info(Object message) {
        log.info(message);
    }

    @Override
    public void info(Object message, Throwable exception) {
        log.info(message, exception);
    }

    @Override
    public void warn(Object message) {
        log.warn(message);
    }

    @Override
    public void warn(Object message, Throwable exception) {
        log.warn(message, exception);
    }

    @Override
    public void error(Object message) {
        log.error(message);
    }

    @Override
    public void error(Object message, Throwable exception) {
        log.error(message, exception);
    }
}
