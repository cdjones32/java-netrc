import co.cdjones.security.auth.NetrcParser;
import co.cdjones.security.auth.Credentials;

public class Test {
    public static void main(String[] args) {
        NetrcParser netrc = NetrcParser.getInstance();
        Credentials credentials = netrc.getCredentials("localhost");

        System.out.println(credentials.user());
    }
}
