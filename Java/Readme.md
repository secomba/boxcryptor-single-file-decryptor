# Build process for Java

The build process was tested with version **9.0.1 of Java** on **Windows 10**. If you have any trouble compiling make sure you have a compatible setup to one of the above.

The code requires the **BouncyCastle** library to work, which you can get from https://www.bouncycastle.org/latest_releases.html. Copy bcprov-jdk*on-*.jar into `/Java/lib`. The code has been tested with bcprov-jdk15on-157.jar.

After you following the steps above you should be able to successfully compile the code with the following commands:

`cd Java`
`javac *.java -cp ./lib/bcprov-jdk15on-157.jar`
`java -cp ".;./lib/bcprov-jdk15on-157.jar" BCFileDecryptor <your parameters>`
