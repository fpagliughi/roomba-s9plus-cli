#[macro_use] extern crate log;

mod api;
mod cli;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use paho_mqtt as mqtt;
use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::process;
use structopt::StructOpt;
use std::str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger from the environment
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or("RUST_LOG", "error")
    );

    let cli = cli::Cli::from_args();

    match cli.command {
        cli::AnyCommand::Unauthenticated(cli::UnauthenticatedCommand::FindIp) => {
            find_ip_address()?;
        }
        cli::AnyCommand::Unauthenticated(cli::UnauthenticatedCommand::GetPassword { address }) => {
            debug!("Getting password for: {}", address);
            get_password(address)?;
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
                .ssl_version(mqtt::SslVersion::Tls_1_2)
                .enable_server_cert_auth(false)
                .finalize();

            debug!("Connecting. Username: '{}', Password: '{}'", cli.username, cli.password);

            let conn_opts = mqtt::ConnectOptionsBuilder::new()
                .mqtt_version(4)
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
        debug!("Broadcasting to UDP socket 5678");
        socket.send_to(&packet[..], "255.255.255.255:5678").unwrap();
        loop {
            if let Ok(length) = socket.recv(&mut data) {
                debug!("Received {} bytes from UDB broadcast.", length);
                if &data[..length] != packet {
                    debug!("{}", str::from_utf8(&data[..length]).unwrap());
                    match serde_json::from_slice::<api::Info>(&data[..length]) {
                        Ok(info) => {
                            if !found.contains(&info.ip) {
                                let hostname = info.hostname.clone();

                                let robot_id = info.robot_id.unwrap_or_else(move || {
                                    let names: Vec<&str> = hostname.split("-").collect();
                                    if names.len() == 2 && (names[0] == "Roomba" || names[0] == "iRobot") {
                                        names[1]
                                    }
                                    else {
                                        "unknown"
                                    }.to_string()
                                });

                                let _ = writeln!(
                                    stdout,
                                    "found.\nHostname: {}\nIP: {}\nblid/robot_id/username: {}",
                                    info.hostname,
                                    info.ip,
                                    robot_id,
                                );
                                found.insert(info.ip);
                            }
                        },
                        Err(err) => warn!("Parsing error: {}", err),
                    }
                }
            }

            let mut fh = stdout.lock();
            let _ = fh.write(b".");
            let _ = fh.flush();
        }
    }
}

fn get_password<A: ToSocketAddrs>(addr: A) -> std::io::Result<()> {
    println!(
        "Warning: please hold the Home button for 2 seconds and check that the ring led is \
        blinking blue."
    );

    let packet: &[u8] = &[0xf0, 0x05, 0xef, 0xcc, 0x3b, 0x29, 0x00];

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let socket = TcpStream::connect(addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut stream = connector.connect("ignore", socket).unwrap();

    let mut stdout = std::io::stdout();
    loop {
        stream.write_all(&packet)?;

        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            if let Some(password) = data
                .rsplit(|&x| x == 0)
                .filter(|x| !x.is_empty())
                .find_map(|x| String::from_utf8(x.to_vec()).ok())
            {
                let _ = writeln!(stdout, "found.\nPassword: {}", password);
                break;
            }
        }

        let mut fh = stdout.lock();
        let _ = fh.write(b".");
        let _ = fh.flush();
    }

    Ok(())
}
