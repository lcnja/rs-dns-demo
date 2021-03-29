use anyhow::Result;
use futures_util::StreamExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::net::UdpSocket;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::proto::rr::dnssec::SupportedAlgorithms;
use trust_dns_client::proto::xfer::SerialMessage;
use trust_dns_client::rr::{LowerName, Name};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::rdata::SOA;
use trust_dns_proto::rr::{DNSClass, RData, Record, RecordType};
use trust_dns_proto::udp::{UdpClientStream, UdpStream};
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::DnsRequest;
use trust_dns_proto::BufStreamHandle;
use trust_dns_server::authority::{Authority, ZoneType};
use trust_dns_server::store::in_memory::InMemoryAuthority;

pub struct DNSServer {
    origin: Name,
    addr: Ipv4Addr,
    port: u32,
    authority: InMemoryAuthority,
    client: AsyncClient,
}

impl DNSServer {
    pub async fn new(
        addr: Ipv4Addr,
        port: u32,
        origin: &str,
        forwarder: Ipv4Addr,
        forwarder_port: u16,
    ) -> Result<Self> {
        let origin: Name = Name::parse(origin, None).unwrap();
        let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

        authority.upsert(
            Record::new()
                .set_name(origin.clone())
                .set_ttl(3600)
                .set_rr_type(RecordType::SOA)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::SOA(SOA::new(
                    Name::parse("sns.dns.icann.org.", None).unwrap(),
                    Name::parse("noc.dns.icann.org.", None).unwrap(),
                    2015082403,
                    7200,
                    3600,
                    1209600,
                    3600,
                )))
                .clone(),
            0,
        );

        authority.upsert(
            Record::new()
                .set_name(origin.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
                .clone(),
            0,
        );

        authority.upsert(
            Record::new()
                .set_name(format!("a.{}", origin).parse()?)
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 2)))
                .clone(),
            0,
        );

        log::info!(
            "Forwarding dns requests to udp://{:?}:{}",
            forwarder,
            forwarder_port,
        );

        let connection = UdpClientStream::<UdpSocket>::new(SocketAddr::new(
            IpAddr::from(forwarder),
            forwarder_port,
        ));

        let (client, request_sender) = AsyncClient::connect(connection).await?;
        let _ = tokio::spawn(request_sender);

        Ok(DNSServer {
            origin,
            addr,
            port,
            authority,
            client,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        tokio::try_join!(self.register_udp())?;

        Ok(())
    }

    async fn register_udp(&self) -> Result<()> {
        log::debug!(
            "Listening for UDP requests at {:?}:{}",
            self.addr,
            self.port
        );

        let socket = UdpSocket::bind(format!("{}:{}", self.addr, self.port)).await?;
        let (mut receiver, sender) = UdpStream::with_bound(socket);

        while let Some(message) = receiver.next().await {
            match message {
                Ok(msg) => {
                    log::debug!("UDP request from {:?}", msg.addr());

                    let client = self.client.clone();
                    let src_addr = msg.addr().clone();
                    let sender = sender.clone();
                    let (name, record_type, mut req) = parse_message(msg).unwrap();
                    if name.contains(self.origin.to_string().as_str()) {
                        log::debug!("local host name: {:?}", name);

                        let lookup = self
                            .authority
                            .lookup(
                                &LowerName::from_str(name.as_str())?,
                                record_type,
                                false,
                                SupportedAlgorithms::new(),
                            )
                            .await?;
                        log::debug!("got lookup: {:?}", lookup);

                        if let Some(record) = lookup.iter().next() {
                            req.add_answer(Record::from_rdata(
                                Name::from_str(name.as_str())?,
                                600,
                                record.clone().into_data(),
                            ));
                        }

                        respond(sender, src_addr, &req);
                    } else {
                        tokio::spawn(async move {
                            if let Some(resp) = forward_request(client, req.clone()).await {
                                respond(sender.clone(), src_addr, &resp).unwrap();
                            }
                        });
                    }
                }

                Err(e) => log::error!("Invalid UDP message received {:?}", e),
            }
        }

        Ok(())
    }
}

fn respond(mut sender: BufStreamHandle, socket_addr: SocketAddr, resp: &Message) -> Option<()> {
    let id = resp.id();
    let response = SerialMessage::new(resp.to_vec().ok()?, socket_addr);

    match sender.send(response) {
        Ok(_) => {
            log::debug!("[{}] Successfully responded back", id);
            log::trace!("[{}] Successfully responded back: {:?}", id, resp);
        }
        Err(e) => {
            log::error!("[{}] Failed to respond back: {:?}", id, e);
        }
    }

    Some(())
}

fn parse_message(message: SerialMessage) -> Option<(String, RecordType, Message)> {
    match Message::from_vec(message.bytes()) {
        Ok(msg) => {
            let mut name: String = "".to_string();
            let mut record_type: RecordType = RecordType::A;

            log::debug!(
                "[{}] parsed message: {} edns: {}",
                msg.id(),
                msg.queries()
                    .first()
                    .map(|q| {
                        name = q.name().to_string();
                        record_type = q.query_type();

                        format!(
                            "{} {} {}",
                            q.name().to_string(),
                            q.query_type(),
                            q.query_class(),
                        )
                    })
                    .unwrap_or_else(|| Default::default(),),
                msg.edns().is_some(),
            );

            Some((name, record_type, msg))
        }
        Err(e) => {
            log::warn!("Failed to parse the message: {}", e);
            None
        }
    }
}

async fn forward_request(mut client: AsyncClient, msg: Message) -> Option<Message> {
    let req = DnsRequest::new(msg, Default::default());
    let id = req.id();

    match client.send(req).await {
        Ok(mut resp) => {
            resp.set_id(id);
            for answer in resp.answers() {
                log::debug!(
                    "[{}] {} {} {} => {}",
                    id,
                    answer.name().to_string(),
                    answer.record_type(),
                    answer.dns_class(),
                    answer.rdata(),
                );
                if let Some(soa) = resp.soa() {
                    log::debug!(
                        "[{}] SOA: {} {}",
                        id,
                        soa.mname().to_string(),
                        soa.rname().to_string()
                    );
                }
            }
            Some(resp.into())
        }
        Err(e) => {
            log::error!("[{}] DNS request failed: {}", id, e);
            None
        }
    }
}
