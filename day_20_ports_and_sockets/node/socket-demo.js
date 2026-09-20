// File: node/socket-demo.js

// File: node/socket-demo.js

"use strict";

const net = require("node:net");

const server = net.createServer((socket) => {
    console.log(
        `Server accepted connection from ${socket.remoteAddress}:${socket.remotePort}`
    );

    socket.setEncoding("utf8");

    socket.on("data", (message) => {
        console.log(`Server received: ${message.trim()}`);
        socket.write("ACK: message received");
    });

    socket.on("end", () => {
        console.log("Client closed its sending side.");
    });
});

server.on("error", (error) => {
    console.error(`Server error: ${error.message}`);
    process.exitCode = 1;
});

server.listen(0, "127.0.0.1", () => {
    const address = server.address();

    if (!address || typeof address === "string") {
        console.error("Unable to determine the server address.");
        server.close();
        return;
    }

    console.log(`Listening on ${address.address}:${address.port}`);

    const client = net.createConnection(
        {
            host: "127.0.0.1",
            port: address.port
        },
        () => {
            const local = `${client.localAddress}:${client.localPort}`;
            const remote = `${client.remoteAddress}:${client.remotePort}`;

            console.log(`Client local endpoint: ${local}`);
            console.log(`Client remote endpoint: ${remote}`);

            client.write("Hello from the TCP client");
        }
    );

    client.setEncoding("utf8");

    client.on("data", (message) => {
        console.log(`Client received: ${message}`);
        client.end();
        server.close();
    });

    client.on("error", (error) => {
        console.error(`Client error: ${error.message}`);
        server.close();
        process.exitCode = 1;
    });

    client.on("close", () => {
        console.log("Client socket closed.");
    });
});
