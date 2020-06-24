mod api;
mod cli;

use paho_mqtt as mqtt;
use std::collections::HashSet;
use std::io::Write;
use std::net::UdpSocket;
use std::process;
use structopt::StructOpt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::from_args();

    match cli.command {
        cli::AnyCommand::Unauthenticated(cli::UnauthenticatedCommand::FindIp) => {
            find_ip_address()?;
        }
        cli::AnyCommand::Authenticated(cli) => {
            // Create a client & define connect options
            let opts = mqtt::CreateOptionsBuilder::new()
                .server_uri(cli.uri)
                .finalize();

            // Create a client & define connect options
            let mut client = mqtt::Client::new(opts).unwrap_or_else(|e| {
                println!("Error creating the client: {:?}", e);
                process::exit(1);
            });

            let ssl_opts = mqtt::SslOptionsBuilder::new()
                .enable_server_cert_auth(false)
                .finalize();

            let conn_opts = mqtt::ConnectOptionsBuilder::new()
                .ssl_options(ssl_opts)
                .user_name(cli.username)
                .password(cli.password)
                .finalize();

            let rx = client.start_consuming();
            client.connect(conn_opts)?;

            match cli.command {
                Some(command) => {
                    let (command, extra) = command.into_command_with_extra();
                    let message = api::Message::new_command(command, extra);

                    message.send_message(&client)?;
                }
                None => {
                    for msg in rx.iter() {
                        if let Some(msg) = msg {
                            println!("{}", msg);
                        }
                    }
                }
            }

            // Disconnect from the broker
            client.disconnect(None).unwrap();
        }
    }

    Ok(())
}

fn find_ip_address() -> std::io::Result<()> {
    let mut found = HashSet::new();
    let mut stdout = std::io::stdout();
    let packet = b"irobotmcs";
    let socket = UdpSocket::bind("0.0.0.0:5678")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut data = [0; 800];

    loop {
        socket.send_to(&packet[..], "255.255.255.255:5678").unwrap();
        loop {
            if let Ok(length) = socket.recv(&mut data) {
                if &data[..length] != packet {
                    if let Ok(info) = serde_json::from_slice::<api::Info>(&data[..length]) {
                        if !found.contains(&info.ip) {
                            let _ = writeln!(
                                stdout,
                                "found.\nHostname: {}\nIP: {}\nblid/robot_id/username: {}",
                                info.hostname, info.ip, info.robot_id
                            );
                            found.insert(info.ip);
                        }
                    }
                }
            }

            let mut fh = stdout.lock();
            let _ = fh.write(b".");
            let _ = fh.flush();
        }
    }
}
