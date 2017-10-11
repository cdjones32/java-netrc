# java-netrc parser
A simple, lightweight component to provide .netrc file parsing in Java applications. Has no dependencies, just a single parser class and Credentials POJO.

I have required this in numerous projects, both simple and complex, so I extracted it from larger libraries for simple use.

## Usage

```java
import co.cdjones.security.auth.NetrcParser;
import co.cdjones.security.auth.Credentials;

public class Test {
    public static void main(String[] args) {
        NetrcParser netrc = NetrcParser.getInstance();
        Credentials credentials = netrc.getCredentials("localhost");

        System.out.println(credentials.user());
    }
}
```

## Getting it
The artifacts are provided by JitPack. Example usage for Gradle:

```groovy
allprojects {
    repositories {
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    compile "com.github.cdjones32:java-netrc:1.0.0"
}
```