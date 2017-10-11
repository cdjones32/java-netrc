package co.cdjones.security.auth;

import lombok.NonNull;
import lombok.SneakyThrows;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.InvalidPropertiesFormatException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author chrisjones
 * @date 11/10/2017
 */
public class NetrcParser {
    private static final Pattern NETRC_TOKEN = Pattern.compile("(\\S+)");

    private enum ParseState {
        START, REQ_KEY, REQ_VALUE, MACHINE, LOGIN, PASSWORD, MACDEF, END;
    }
    
    private File netrc;
    private long lastModified;
    private Map<String,Credentials> hosts = new HashMap<>();


    /**
     * getInstance.
     *
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance() {
        File netrc = getDefaultFile();
        return getInstance(netrc);
    }

    /**
     * getInstance.
     *
     * @param netrcPath a {@link java.lang.String} object.
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance(@NonNull String netrcPath) {
        File netrc = new File(netrcPath);
        return netrc.exists() ? getInstance(new File(netrcPath)) : null;
    }

    /**
     * getInstance.
     *
     * @param netrc a {@link java.io.File} object.
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance(File netrc) {
        return new NetrcParser(netrc).parse();
    }

    private static File getDefaultFile() {
        File home = new File(System.getProperty("user.home"));
        File netrc = new File(home, ".netrc");
        if (!netrc.exists()) netrc = new File(home, "_netrc"); // windows variant
        return netrc;
    }

    /**
     * getCredentials.
     *
     * @param host a {@link java.lang.String} object.
     * @return a {@link Credentials} object.
     */
    public synchronized Credentials getCredentials(String host) {
        if (!this.netrc.exists()) return null;
        if (this.lastModified != this.netrc.lastModified()) parse();
        return this.hosts.get(host);
    }

    private NetrcParser(File netrc) {
        this.netrc = netrc;
    }

    @SneakyThrows
    synchronized private NetrcParser parse() {
        if (!netrc.exists()) return this;

        this.hosts.clear();
        this.lastModified = this.netrc.lastModified();

        try (BufferedReader r = new BufferedReader(new InputStreamReader(Files.newInputStream(netrc.toPath()), Charset.defaultCharset()))) {
            String line;
            String machine = null;
            String login = null;
            String password = null;

            ParseState state = ParseState.START;
            Matcher matcher = NETRC_TOKEN.matcher("");

            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    if (state == ParseState.MACDEF) {
                        state = ParseState.REQ_KEY;
                    }
                    continue;
                }

                matcher.reset(line);
                while (matcher.find()) {
                    String match = matcher.group();
                    switch (state) {
                        case START:
                            if ("machine".equals(match)) {
                                state = ParseState.MACHINE;
                            }
                            break;

                        case REQ_KEY:
                            if ("login".equals(match)) {
                                state = ParseState.LOGIN;
                            }
                            else if ("password".equals(match)) {
                                state = ParseState.PASSWORD;
                            }
                            else if ("macdef".equals(match)) {
                                state = ParseState.MACDEF;
                            }
                            else if ("machine".equals(match)) {
                                state = ParseState.MACHINE;
                            }
                            else {
                                state = ParseState.REQ_VALUE;
                            }
                            break;

                        case REQ_VALUE:
                            state = ParseState.REQ_KEY;
                            break;

                        case MACHINE:
                            if (machine != null && login != null && password != null) {
                                this.hosts.put(
                                    machine,
                                    Credentials.builder()
                                        .host(machine)
                                        .user(login)
                                        .password(password)
                                        .build()
                                );
                            }
                            machine = match;
                            login = null;
                            password = null;
                            state = ParseState.REQ_KEY;
                            break;

                        case LOGIN:
                            login = match;
                            state = ParseState.REQ_KEY;
                            break;

                        case PASSWORD:
                            password = match;
                            state = ParseState.REQ_KEY;
                            break;

                        case MACDEF:
                            // Only way out is an empty line, handled before the find() loop.
                            break;
                    }
                }
            }
            if (machine != null) {
                if (login != null && password != null) {
                    this.hosts.put(
                        machine,
                        Credentials.builder()
                            .host(machine)
                            .user(login)
                            .password(password)
                            .build()
                    );
                }
            }

        } catch (IOException e) {
            throw new InvalidPropertiesFormatException("Invalid netrc file: '" + this.netrc.getAbsolutePath() + "'");
        }

        return this;
    }

}
