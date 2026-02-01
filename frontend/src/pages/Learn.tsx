import { useState } from 'react'
import { useLanguage } from '../i18n/LanguageContext'

type Section = 'intro' | 'how' | 'root' | 'intermediate' | 'server' | 'client' | 'ssl' | 'formats' | 'crypto' | 'keysize' | 'hash' | 'renewal' | 'expiry' | 'best' | 'examples'

const styles = {
  card: {
    background: 'var(--card-bg)',
    borderRadius: '8px',
    padding: '1.5rem',
    border: '1px solid var(--border)',
  },
  sectionTitle: {
    marginBottom: '1rem',
    color: 'var(--primary)',
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  paragraph: {
    marginBottom: '1rem',
    lineHeight: 1.8,
    color: 'var(--text)',
  },
  infoBox: {
    padding: '1.25rem',
    borderRadius: '8px',
    marginBottom: '1rem',
  },
  listItem: {
    lineHeight: 2,
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    marginBottom: '1rem',
  },
  th: {
    textAlign: 'left' as const,
    padding: '0.75rem',
    borderBottom: '2px solid var(--border)',
    fontWeight: 600,
    color: 'var(--text)',
  },
  td: {
    padding: '0.75rem',
    borderBottom: '1px solid var(--border)',
    color: 'var(--text)',
  },
}

function Learn() {
  const { lang, t } = useLanguage()
  const [activeSection, setActiveSection] = useState<Section>('intro')

  const sections: { id: Section; title: string }[] = [
    { id: 'intro', title: t('learn.sections.intro') },
    { id: 'how', title: t('learn.sections.how') },
    { id: 'root', title: t('learn.sections.root') },
    { id: 'intermediate', title: t('learn.sections.intermediate') },
    { id: 'server', title: t('learn.sections.server') },
    { id: 'client', title: t('learn.sections.client') },
    { id: 'ssl', title: t('learn.sections.ssl') },
    { id: 'formats', title: t('learn.sections.formats') },
    { id: 'crypto', title: t('learn.sections.crypto') },
    { id: 'keysize', title: t('learn.sections.keysize') },
    { id: 'hash', title: t('learn.sections.hash') },
    { id: 'renewal', title: t('learn.sections.renewal') },
    { id: 'expiry', title: t('learn.sections.expiry') },
    { id: 'best', title: t('learn.sections.best') },
    { id: 'examples', title: t('learn.sections.examples') },
  ]

  const InfoBox = ({ type, title, children }: { type: 'info' | 'success' | 'warning' | 'danger' | 'primary'; title?: string; children: React.ReactNode }) => {
    const colors = {
      info: { bg: 'var(--card-bg)', border: 'var(--primary)', text: 'var(--text)' },
      success: { bg: 'var(--card-bg)', border: 'var(--success)', text: 'var(--text)' },
      warning: { bg: 'var(--card-bg)', border: 'var(--warning)', text: 'var(--text)' },
      danger: { bg: 'var(--card-bg)', border: 'var(--danger)', text: 'var(--text)' },
      primary: { bg: 'var(--card-bg)', border: 'var(--primary)', text: 'var(--text)' },
    }
    const c = colors[type]
    return (
      <div style={{ ...styles.infoBox, background: c.bg, border: `2px solid ${c.border}` }}>
        {title && <strong style={{ color: c.border, display: 'block', marginBottom: '0.5rem' }}>{title}</strong>}
        <div style={{ color: c.text, fontSize: '0.925rem', lineHeight: 1.7 }}>{children}</div>
      </div>
    )
  }

  const Badge = ({ color, children }: { color: 'primary' | 'success' | 'warning' | 'danger' | 'info'; children: React.ReactNode }) => (
    <span style={{
      display: 'inline-block',
      padding: '0.25rem 0.75rem',
      borderRadius: '9999px',
      fontSize: '0.75rem',
      fontWeight: 600,
      background: `var(--${color})`,
      color: 'white',
    }}>
      {children}
    </span>
  )

  const renderIntro = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{t('learn.intro.title')}</h2>
      <p style={styles.paragraph}>
        <strong>{t('learn.intro.p1')}</strong>
      </p>

      <InfoBox type="info" title={t('learn.intro.analogyTitle')}>
        <p style={{ marginBottom: '0.75rem' }}>{t('learn.intro.analogyP1')}</p>
        <p>{t('learn.intro.analogyP2')}</p>
      </InfoBox>

      <h3 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{t('learn.intro.contentsTitle')}</h3>
      <ul style={{ marginLeft: '1.5rem' }}>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Ime vlasnika' : 'Owner name'}</strong> - {lang === 'sr' ? 'ko poseduje sertifikat (npr. "google.com")' : 'who owns the certificate (e.g., "google.com")'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Javni ključ' : 'Public key'}</strong> - {lang === 'sr' ? 'koristi se za šifrovanje podataka' : 'used for encrypting data'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Ko ga je izdao' : 'Issuer'}</strong> - {lang === 'sr' ? 'Certificate Authority koji garantuje identitet' : 'Certificate Authority that guarantees the identity'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Rok važenja' : 'Validity period'}</strong> - {lang === 'sr' ? 'od kada do kada važi' : "when it's valid from and until"}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Digitalni potpis' : 'Digital signature'}</strong> - {lang === 'sr' ? 'dokaz da nije falsifikovan' : "proof it hasn't been forged"}</li>
      </ul>
    </div>
  )

  const renderHow = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Kako funkcionišu sertifikati?' : 'How do certificates work?'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Sertifikati koriste asimetričnu kriptografiju - sistem sa dva ključa: javnim i privatnim.'
          : 'Certificates use asymmetric cryptography - a system with two keys: public and private.'}
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <InfoBox type="success" title={lang === 'sr' ? 'Javni ključ' : 'Public Key'}>
          {lang === 'sr'
            ? 'Deli se sa svima. Koristi se za šifrovanje podataka i verifikaciju potpisa.'
            : 'Shared with everyone. Used for encrypting data and verifying signatures.'}
        </InfoBox>
        <InfoBox type="danger" title={lang === 'sr' ? 'Privatni ključ' : 'Private Key'}>
          {lang === 'sr'
            ? 'Strogo čuvan u tajnosti! Koristi se za dešifrovanje i potpisivanje.'
            : 'Kept strictly secret! Used for decryption and signing.'}
        </InfoBox>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Proces uspostavljanja HTTPS veze' : 'HTTPS connection process'}</h3>
      <div style={{ position: 'relative', paddingLeft: '2rem' }}>
        <div style={{ position: 'absolute', left: '0.5rem', top: 0, bottom: 0, width: '2px', background: 'var(--border)' }} />
        {[
          { step: 1, title: lang === 'sr' ? 'Browser traži sajt' : 'Browser requests site', desc: lang === 'sr' ? 'Kucate https://banka.rs u browser' : 'You type https://bank.com in browser' },
          { step: 2, title: lang === 'sr' ? 'Server šalje sertifikat' : 'Server sends certificate', desc: lang === 'sr' ? 'Server šalje svoj digitalni sertifikat browseru' : 'Server sends its digital certificate to the browser' },
          { step: 3, title: lang === 'sr' ? 'Browser verifikuje' : 'Browser verifies', desc: lang === 'sr' ? 'Browser proverava da li je sertifikat validan i da li mu veruje' : 'Browser checks if certificate is valid and trusted' },
          { step: 4, title: lang === 'sr' ? 'Razmena ključeva' : 'Key exchange', desc: lang === 'sr' ? 'Browser i server se dogovaraju o tajnom ključu za šifrovanje' : 'Browser and server agree on a secret key for encryption' },
          { step: 5, title: lang === 'sr' ? 'Šifrovana komunikacija' : 'Encrypted communication', desc: lang === 'sr' ? 'Svi podaci se šifruju - niko ne može da "prisluškuje"' : 'All data is encrypted - no one can eavesdrop' },
        ].map(item => (
          <div key={item.step} style={{ marginBottom: '1.25rem', position: 'relative' }}>
            <div style={{
              position: 'absolute',
              left: '-1.75rem',
              width: '1.5rem',
              height: '1.5rem',
              borderRadius: '50%',
              background: 'var(--primary)',
              color: 'white',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.75rem',
              fontWeight: 'bold'
            }}>
              {item.step}
            </div>
            <h4 style={{ marginBottom: '0.25rem', color: 'var(--text)' }}>{item.title}</h4>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{item.desc}</p>
          </div>
        ))}
      </div>
    </div>
  )

  const renderRoot = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>Root CA (Root Certificate Authority)</h2>
      <InfoBox type="primary" title={lang === 'sr' ? 'Root CA je "vrhovna vlast" u svetu sertifikata' : 'Root CA is the "supreme authority" in the certificate world'}>
        {lang === 'sr'
          ? 'To je organizacija kojoj svi veruju i koja može da izdaje sertifikate drugim organizacijama.'
          : 'It is an organization that everyone trusts and that can issue certificates to other organizations.'}
      </InfoBox>

      <h3 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Karakteristike Root CA:' : 'Root CA characteristics:'}</h3>
      <ul style={{ marginLeft: '1.5rem', marginBottom: '1.5rem' }}>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Sam sebe potpisuje' : 'Self-signed'}</strong> - {lang === 'sr' ? 'nema nikoga "iznad" njega' : 'no one is "above" it'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Ugrađen u OS/Browser' : 'Built into OS/Browser'}</strong> - {lang === 'sr' ? 'Windows, macOS, Chrome, Firefox... svi imaju listu Root CA kojima veruju' : 'Windows, macOS, Chrome, Firefox... all have a list of trusted Root CAs'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Izuzetno zaštićen' : 'Extremely protected'}</strong> - {lang === 'sr' ? 'privatni ključ se čuva u specijalnim hardverskim modulima, često offline' : 'private key is stored in special hardware modules, often offline'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Dugo važi' : 'Long validity'}</strong> - {lang === 'sr' ? 'obično 20-30 godina' : 'usually 20-30 years'}</li>
      </ul>

      <div style={{ ...styles.infoBox, background: 'var(--card-bg)', border: '1px solid var(--border)' }}>
        <h4 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Poznati Root CA-ovi:' : 'Well-known Root CAs:'}</h4>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {['DigiCert', "Let's Encrypt", 'Comodo', 'GlobalSign', 'Entrust', 'GoDaddy'].map(ca => (
            <Badge key={ca} color="info">{ca}</Badge>
          ))}
        </div>
      </div>

      <InfoBox type="warning" title={lang === 'sr' ? 'Zašto je Root CA važan?' : 'Why is Root CA important?'}>
        {lang === 'sr'
          ? 'Ako neko kompromituje Root CA, može da izdaje lažne sertifikate za bilo koji sajt. Zato se Root CA ključevi čuvaju kao najveća tajna i koriste se samo za potpisivanje Intermediate CA sertifikata.'
          : 'If someone compromises a Root CA, they can issue fake certificates for any site. That\'s why Root CA keys are kept as the biggest secret and used only for signing Intermediate CA certificates.'}
      </InfoBox>
    </div>
  )

  const renderIntermediate = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>Intermediate CA</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Intermediate CA je "posrednik" između Root CA i krajnjih sertifikata. Root CA izdaje sertifikat Intermediate CA-u, a Intermediate CA izdaje sertifikate sajtovima i korisnicima.'
          : 'Intermediate CA is a "middleman" between Root CA and end certificates. Root CA issues a certificate to Intermediate CA, and Intermediate CA issues certificates to sites and users.'}
      </p>

      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '0.5rem',
        padding: '2rem',
        background: 'var(--bg)',
        borderRadius: '8px',
        marginBottom: '1.5rem',
        border: '1px solid var(--border)'
      }}>
        <div style={{ padding: '1rem 2rem', background: 'var(--primary)', color: 'white', borderRadius: '8px', fontWeight: 'bold' }}>Root CA</div>
        <div style={{ fontSize: '1.5rem', color: 'var(--text-muted)' }}>|</div>
        <div style={{ padding: '1rem 2rem', background: 'var(--success)', color: 'white', borderRadius: '8px', fontWeight: 'bold' }}>Intermediate CA</div>
        <div style={{ fontSize: '1.5rem', color: 'var(--text-muted)' }}>|</div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <div style={{ padding: '0.75rem 1.5rem', background: 'var(--warning)', color: 'white', borderRadius: '8px', fontSize: '0.875rem' }}>Server Cert</div>
          <div style={{ padding: '0.75rem 1.5rem', background: 'var(--warning)', color: 'white', borderRadius: '8px', fontSize: '0.875rem' }}>Client Cert</div>
        </div>
      </div>

      <h3 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Zašto koristimo Intermediate CA?' : 'Why use Intermediate CA?'}</h3>
      <div style={{ display: 'grid', gap: '1rem' }}>
        {[
          { title: lang === 'sr' ? 'Bezbednost' : 'Security', desc: lang === 'sr' ? 'Root CA privatni ključ može ostati offline. Ako se kompromituje Intermediate CA, može se povući bez uticaja na Root CA.' : 'Root CA private key can stay offline. If Intermediate CA is compromised, it can be revoked without affecting Root CA.', color: 'success' },
          { title: lang === 'sr' ? 'Fleksibilnost' : 'Flexibility', desc: lang === 'sr' ? 'Možete imati više Intermediate CA za različite svrhe (jedan za servere, jedan za korisnike, itd.)' : 'You can have multiple Intermediate CAs for different purposes (one for servers, one for users, etc.)', color: 'info' },
          { title: lang === 'sr' ? 'Upravljanje' : 'Management', desc: lang === 'sr' ? 'Lakše je upravljati i pratiti ko izdaje sertifikate kada imate hijerarhiju.' : 'It\'s easier to manage and track who issues certificates when you have a hierarchy.', color: 'primary' },
        ].map(item => (
          <InfoBox key={item.title} type={item.color as any} title={item.title}>
            {item.desc}
          </InfoBox>
        ))}
      </div>
    </div>
  )

  const renderServer = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Server sertifikati (SSL/TLS)' : 'Server certificates (SSL/TLS)'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Server sertifikat dokazuje identitet web sajta ili servera. Kada vidite zeleni katanac u browseru, to znači da sajt ima validan server sertifikat.'
          : 'A server certificate proves the identity of a website or server. When you see a green padlock in your browser, it means the site has a valid server certificate.'}
      </p>

      <div style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)', marginBottom: '1.5rem' }}>
        <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Server sertifikat garantuje:' : 'Server certificate guarantees:'}</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
          {[
            { icon: 'lock', title: lang === 'sr' ? 'Enkripcija' : 'Encryption', desc: lang === 'sr' ? 'Podaci između vas i sajta su šifrovani' : 'Data between you and the site is encrypted' },
            { icon: 'check', title: lang === 'sr' ? 'Autentičnost' : 'Authenticity', desc: lang === 'sr' ? 'Zaista komunicirate sa pravim sajtom' : 'You are really communicating with the real site' },
            { icon: 'shield', title: lang === 'sr' ? 'Integritet' : 'Integrity', desc: lang === 'sr' ? 'Podaci nisu izmenjeni u prenosu' : 'Data was not modified in transit' },
          ].map(item => (
            <div key={item.title} style={{ textAlign: 'center', padding: '1rem' }}>
              <h4 style={{ color: 'var(--text)' }}>{item.title}</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>{item.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <h3 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Tipovi server sertifikata:' : 'Server certificate types:'}</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{lang === 'sr' ? 'Tip' : 'Type'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Opis' : 'Description'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Primer' : 'Example'}</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}><Badge color="info">Single Domain</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Važi samo za jedan domen' : 'Valid for one domain only'}</td>
            <td style={styles.td}>www.example.com</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="success">Wildcard</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Važi za sve poddomene' : 'Valid for all subdomains'}</td>
            <td style={styles.td}>*.example.com</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="warning">Multi-Domain (SAN)</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Važi za više različitih domena' : 'Valid for multiple different domains'}</td>
            <td style={styles.td}>example.com, example.org</td>
          </tr>
        </tbody>
      </table>
    </div>
  )

  const renderClient = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Client sertifikati' : 'Client certificates'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Dok server sertifikati dokazuju identitet servera, client sertifikati dokazuju identitet korisnika ili uređaja. To je kao digitalna lična karta za vaš računar.'
          : 'While server certificates prove server identity, client certificates prove user or device identity. It\'s like a digital ID card for your computer.'}
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <InfoBox type="primary" title={lang === 'sr' ? 'Server sertifikat' : 'Server certificate'}>
          <p style={{ marginBottom: '0.5rem' }}><strong>{lang === 'sr' ? 'Pitanje:' : 'Question:'}</strong> "{lang === 'sr' ? 'Da li je ovo pravi sajt banke?' : 'Is this the real bank site?'}"</p>
          <p>{lang === 'sr' ? 'Server dokazuje svoj identitet korisniku' : 'Server proves its identity to the user'}</p>
        </InfoBox>
        <InfoBox type="success" title={lang === 'sr' ? 'Client sertifikat' : 'Client certificate'}>
          <p style={{ marginBottom: '0.5rem' }}><strong>{lang === 'sr' ? 'Pitanje:' : 'Question:'}</strong> "{lang === 'sr' ? 'Da li je ovo pravi korisnik Marko?' : 'Is this the real user John?'}"</p>
          <p>{lang === 'sr' ? 'Korisnik dokazuje svoj identitet serveru' : 'User proves their identity to the server'}</p>
        </InfoBox>
      </div>

      <h3 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Kada se koriste client sertifikati?' : 'When are client certificates used?'}</h3>
      <ul style={{ marginLeft: '1.5rem', marginBottom: '1.5rem' }}>
        <li style={styles.listItem}><strong>VPN {lang === 'sr' ? 'pristup' : 'access'}</strong> - {lang === 'sr' ? 'umesto username/password, koristi se sertifikat' : 'instead of username/password, a certificate is used'}</li>
        <li style={styles.listItem}><strong>{lang === 'sr' ? 'Korporativne mreže' : 'Corporate networks'}</strong> - {lang === 'sr' ? 'samo uređaji sa sertifikatom mogu pristupiti' : 'only devices with certificates can access'}</li>
        <li style={styles.listItem}><strong>IoT {lang === 'sr' ? 'uređaji' : 'devices'}</strong> - {lang === 'sr' ? 'svaki uređaj ima svoj sertifikat' : 'each device has its own certificate'}</li>
        <li style={styles.listItem}><strong>Email {lang === 'sr' ? 'potpisivanje' : 'signing'} (S/MIME)</strong> - {lang === 'sr' ? 'digitalno potpisivanje emailova' : 'digitally signing emails'}</li>
        <li style={styles.listItem}><strong>Mutual TLS (mTLS)</strong> - {lang === 'sr' ? 'i server i klijent se autentifikuju' : 'both server and client authenticate'}</li>
      </ul>

      <InfoBox type="success" title={lang === 'sr' ? 'Prednost nad lozinkama:' : 'Advantage over passwords:'}>
        {lang === 'sr'
          ? 'Client sertifikati su sigurniji od lozinki jer se privatni ključ nikada ne šalje preko mreže. Čak i ako neko presretne komunikaciju, ne može da se predstavi kao vi.'
          : 'Client certificates are more secure than passwords because the private key is never sent over the network. Even if someone intercepts the communication, they cannot impersonate you.'}
      </InfoBox>
    </div>
  )

  const renderSsl = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'SSL/TLS protokoli' : 'SSL/TLS Protocols'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'SSL (Secure Sockets Layer) i TLS (Transport Layer Security) su kriptografski protokoli koji obezbeđuju sigurnu komunikaciju preko interneta. TLS je naslednik SSL-a i danas se koristi za sve HTTPS veze.'
          : 'SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are cryptographic protocols that provide secure communication over the internet. TLS is the successor to SSL and is used today for all HTTPS connections.'}
      </p>

      <InfoBox type="info" title={lang === 'sr' ? 'Kratka istorija' : 'Brief History'}>
        <ul style={{ marginLeft: '1.25rem' }}>
          <li><strong>1995:</strong> SSL 2.0 - {lang === 'sr' ? 'prvi javno objavljen protokol (Netscape)' : 'first publicly released protocol (Netscape)'}</li>
          <li><strong>1996:</strong> SSL 3.0 - {lang === 'sr' ? 'značajno poboljšanje, ali ima ranjivosti' : 'major improvement, but has vulnerabilities'}</li>
          <li><strong>1999:</strong> TLS 1.0 - {lang === 'sr' ? 'standardizovana verzija SSL 3.0 (RFC 2246)' : 'standardized version of SSL 3.0 (RFC 2246)'}</li>
          <li><strong>2006:</strong> TLS 1.1 - {lang === 'sr' ? 'poboljšana zaštita od napada' : 'improved attack protection'}</li>
          <li><strong>2008:</strong> TLS 1.2 - {lang === 'sr' ? 'podrška za SHA-256, fleksibilniji' : 'SHA-256 support, more flexible'}</li>
          <li><strong>2018:</strong> TLS 1.3 - {lang === 'sr' ? 'moderni protokol, brži i sigurniji' : 'modern protocol, faster and more secure'}</li>
        </ul>
      </InfoBox>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Verzije i status' : 'Versions and Status'}</h3>
      <div style={{ display: 'grid', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={{ ...styles.infoBox, background: 'var(--card-bg)', border: '2px solid var(--danger)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ margin: 0, color: 'var(--danger)' }}>SSL 2.0 & SSL 3.0</h4>
            <Badge color="danger">{lang === 'sr' ? 'ZASTARELO' : 'DEPRECATED'}</Badge>
          </div>
          <p style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>
            {lang === 'sr'
              ? 'Ovi protokoli imaju ozbiljne sigurnosne ranjivosti i nikada se ne smeju koristiti.'
              : 'These protocols have serious security vulnerabilities and must never be used.'}
          </p>
          <ul style={{ marginLeft: '1.25rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            <li><strong>POODLE</strong> (2014) - {lang === 'sr' ? 'napad na SSL 3.0' : 'attack on SSL 3.0'}</li>
            <li><strong>DROWN</strong> (2016) - {lang === 'sr' ? 'napad preko SSL 2.0' : 'attack via SSL 2.0'}</li>
          </ul>
        </div>

        <div style={{ ...styles.infoBox, background: 'var(--card-bg)', border: '2px solid var(--warning)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ margin: 0, color: 'var(--warning)' }}>TLS 1.0 & TLS 1.1</h4>
            <Badge color="warning">{lang === 'sr' ? 'ZASTARELO (2020)' : 'DEPRECATED (2020)'}</Badge>
          </div>
          <p style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>
            {lang === 'sr'
              ? 'Zvanično zastareli u martu 2021. Većina modernih browsera ih više ne podržava.'
              : 'Officially deprecated in March 2021. Most modern browsers no longer support them.'}
          </p>
          <ul style={{ marginLeft: '1.25rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            <li><strong>BEAST</strong> (2011) - {lang === 'sr' ? 'napad na TLS 1.0' : 'attack on TLS 1.0'}</li>
            <li>{lang === 'sr' ? 'Slabi cipher suites' : 'Weak cipher suites'}</li>
          </ul>
        </div>

        <div style={{ ...styles.infoBox, background: 'var(--card-bg)', border: '2px solid var(--success)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ margin: 0, color: 'var(--success)' }}>TLS 1.2</h4>
            <Badge color="success">{lang === 'sr' ? 'PREPORUČENO' : 'RECOMMENDED'}</Badge>
          </div>
          <p style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>
            {lang === 'sr'
              ? 'Trenutno najšire korišćena verzija. Siguran kada se pravilno konfiguriše.'
              : 'Currently the most widely used version. Secure when properly configured.'}
          </p>
          <ul style={{ marginLeft: '1.25rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            <li>{lang === 'sr' ? 'Podrška za SHA-256 i novije algoritme' : 'Support for SHA-256 and newer algorithms'}</li>
            <li>{lang === 'sr' ? 'AEAD cipher modes (GCM)' : 'AEAD cipher modes (GCM)'}</li>
            <li>{lang === 'sr' ? 'Fleksibilno dogovaranje algoritama' : 'Flexible algorithm negotiation'}</li>
          </ul>
        </div>

        <div style={{ ...styles.infoBox, background: 'var(--card-bg)', border: '2px solid var(--primary)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h4 style={{ margin: 0, color: 'var(--primary)' }}>TLS 1.3</h4>
            <Badge color="primary">{lang === 'sr' ? 'NAJBOLJI IZBOR' : 'BEST CHOICE'}</Badge>
          </div>
          <p style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>
            {lang === 'sr'
              ? 'Najnovija verzija sa značajnim poboljšanjima sigurnosti i performansi.'
              : 'Latest version with significant security and performance improvements.'}
          </p>
          <ul style={{ marginLeft: '1.25rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            <li><strong>0-RTT:</strong> {lang === 'sr' ? 'Brži handshake (1 round-trip umesto 2)' : 'Faster handshake (1 round-trip instead of 2)'}</li>
            <li><strong>Forward Secrecy:</strong> {lang === 'sr' ? 'Obavezan za sve veze' : 'Mandatory for all connections'}</li>
            <li>{lang === 'sr' ? 'Uklonjeni zastareli algoritmi (RSA key exchange, CBC, RC4, 3DES)' : 'Removed obsolete algorithms (RSA key exchange, CBC, RC4, 3DES)'}</li>
            <li>{lang === 'sr' ? 'Šifrovan handshake (više privatnosti)' : 'Encrypted handshake (more privacy)'}</li>
          </ul>
        </div>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'TLS Handshake proces' : 'TLS Handshake Process'}</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.75rem', color: 'var(--success)' }}>TLS 1.2 Handshake</h4>
          <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
            <div style={{ position: 'absolute', left: '0.4rem', top: 0, bottom: 0, width: '2px', background: 'var(--border)' }} />
            {[
              'Client Hello',
              'Server Hello + Certificate',
              'Server Key Exchange',
              'Client Key Exchange',
              'Finished (both sides)',
            ].map((step, i) => (
              <div key={i} style={{ marginBottom: '0.5rem', position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  left: '-1.25rem',
                  width: '1rem',
                  height: '1rem',
                  borderRadius: '50%',
                  background: 'var(--success)',
                  fontSize: '0.625rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'white',
                  fontWeight: 'bold'
                }}>{i + 1}</div>
                <span style={{ fontSize: '0.875rem', color: 'var(--text)' }}>{step}</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {lang === 'sr' ? '2 round-trips potrebno' : '2 round-trips required'}
          </p>
        </div>

        <div style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.75rem', color: 'var(--primary)' }}>TLS 1.3 Handshake</h4>
          <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
            <div style={{ position: 'absolute', left: '0.4rem', top: 0, bottom: 0, width: '2px', background: 'var(--border)' }} />
            {[
              'Client Hello + Key Share',
              'Server Hello + Key Share + Certificate + Finished',
              'Client Finished',
            ].map((step, i) => (
              <div key={i} style={{ marginBottom: '0.5rem', position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  left: '-1.25rem',
                  width: '1rem',
                  height: '1rem',
                  borderRadius: '50%',
                  background: 'var(--primary)',
                  fontSize: '0.625rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'white',
                  fontWeight: 'bold'
                }}>{i + 1}</div>
                <span style={{ fontSize: '0.875rem', color: 'var(--text)' }}>{step}</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {lang === 'sr' ? '1 round-trip potreban (brže!)' : '1 round-trip required (faster!)'}
          </p>
        </div>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Cipher Suites' : 'Cipher Suites'}</h3>
      <p style={{ ...styles.paragraph, marginBottom: '1rem' }}>
        {lang === 'sr'
          ? 'Cipher suite je kombinacija algoritama koja se koristi za šifrovanje. Format naziva opisuje komponente:'
          : 'A cipher suite is a combination of algorithms used for encryption. The naming format describes the components:'}
      </p>
      <div style={{ background: 'var(--bg)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', border: '1px solid var(--border)' }}>
        <code style={{ fontSize: '0.875rem', color: 'var(--primary)' }}>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</code>
        <table style={{ ...styles.table, marginTop: '1rem' }}>
          <tbody>
            <tr>
              <td style={{ ...styles.td, fontWeight: 'bold' }}>TLS</td>
              <td style={styles.td}>{lang === 'sr' ? 'Protokol' : 'Protocol'}</td>
            </tr>
            <tr>
              <td style={{ ...styles.td, fontWeight: 'bold' }}>ECDHE</td>
              <td style={styles.td}>{lang === 'sr' ? 'Razmena ključeva (Elliptic Curve Diffie-Hellman Ephemeral)' : 'Key exchange (Elliptic Curve Diffie-Hellman Ephemeral)'}</td>
            </tr>
            <tr>
              <td style={{ ...styles.td, fontWeight: 'bold' }}>RSA</td>
              <td style={styles.td}>{lang === 'sr' ? 'Autentifikacija servera' : 'Server authentication'}</td>
            </tr>
            <tr>
              <td style={{ ...styles.td, fontWeight: 'bold' }}>AES_256_GCM</td>
              <td style={styles.td}>{lang === 'sr' ? 'Bulk šifrovanje (256-bit AES u GCM modu)' : 'Bulk encryption (256-bit AES in GCM mode)'}</td>
            </tr>
            <tr>
              <td style={{ ...styles.td, fontWeight: 'bold' }}>SHA384</td>
              <td style={styles.td}>{lang === 'sr' ? 'Hash za MAC' : 'Hash for MAC'}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Preporučeni Cipher Suites' : 'Recommended Cipher Suites'}</h3>
      <div style={{ display: 'grid', gap: '0.5rem', marginBottom: '1.5rem' }}>
        {[
          { suite: 'TLS_AES_256_GCM_SHA384', version: 'TLS 1.3', badge: 'primary' },
          { suite: 'TLS_AES_128_GCM_SHA256', version: 'TLS 1.3', badge: 'primary' },
          { suite: 'TLS_CHACHA20_POLY1305_SHA256', version: 'TLS 1.3', badge: 'primary' },
          { suite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', version: 'TLS 1.2', badge: 'success' },
          { suite: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', version: 'TLS 1.2', badge: 'success' },
          { suite: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', version: 'TLS 1.2', badge: 'success' },
        ].map(item => (
          <div key={item.suite} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 1rem', background: 'var(--bg)', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <Badge color={item.badge as any}>{item.version}</Badge>
            <code style={{ fontSize: '0.8rem', color: 'var(--text)' }}>{item.suite}</code>
          </div>
        ))}
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Primeri konfiguracije' : 'Configuration Examples'}</h3>
      <div style={{ display: 'grid', gap: '1rem' }}>
        <div style={{ background: 'var(--bg)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>Nginx</h4>
          <pre style={{ fontSize: '0.75rem', overflow: 'auto', color: 'var(--text-muted)', margin: 0 }}>
{`ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;`}
          </pre>
        </div>

        <div style={{ background: 'var(--bg)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>Apache</h4>
          <pre style={{ fontSize: '0.75rem', overflow: 'auto', color: 'var(--text-muted)', margin: 0 }}>
{`SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on`}
          </pre>
        </div>

        <div style={{ background: 'var(--bg)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.5rem', color: 'var(--text)' }}>OpenSSL {lang === 'sr' ? '(testiranje)' : '(testing)'}</h4>
          <pre style={{ fontSize: '0.75rem', overflow: 'auto', color: 'var(--text-muted)', margin: 0 }}>
{`# Provera podržanih protokola
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Prikaz sertifikata i cipher suite-a
openssl s_client -connect example.com:443 -showcerts`}
          </pre>
        </div>
      </div>

      <InfoBox type="warning" title={lang === 'sr' ? 'Važno za kompatibilnost' : 'Important for Compatibility'}>
        {lang === 'sr'
          ? 'Ako morate podržavati starije klijente (npr. Windows 7 bez update-a), možda ćete morati da zadržite TLS 1.2. Međutim, nikada nemojte omogućiti TLS 1.0/1.1 ili SSL. Koristite alate kao SSL Labs (ssllabs.com) za testiranje konfiguracije.'
          : 'If you need to support older clients (e.g., Windows 7 without updates), you may need to keep TLS 1.2. However, never enable TLS 1.0/1.1 or SSL. Use tools like SSL Labs (ssllabs.com) to test your configuration.'}
      </InfoBox>
    </div>
  )

  const renderFormats = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Formati sertifikata' : 'Certificate Formats'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Sertifikati se mogu sačuvati u različitim formatima. Svaki format ima svoje prednosti i koristi se u različitim situacijama.'
          : 'Certificates can be saved in various formats. Each format has its advantages and is used in different situations.'}
      </p>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Pregled formata' : 'Format Overview'}</h3>
      <table style={{ ...styles.table, marginBottom: '1.5rem' }}>
        <thead>
          <tr>
            <th style={styles.th}>{lang === 'sr' ? 'Format' : 'Format'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Ekstenzije' : 'Extensions'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Encoding' : 'Encoding'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Sadrži' : 'Contains'}</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}><Badge color="primary">PEM</Badge></td>
            <td style={styles.td}>.pem, .crt, .cer, .key</td>
            <td style={styles.td}>Base64 (ASCII)</td>
            <td style={styles.td}>{lang === 'sr' ? 'Sertifikat i/ili ključ' : 'Certificate and/or key'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="success">DER</Badge></td>
            <td style={styles.td}>.der, .cer</td>
            <td style={styles.td}>Binary</td>
            <td style={styles.td}>{lang === 'sr' ? 'Samo sertifikat' : 'Certificate only'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="info">PKCS#7</Badge></td>
            <td style={styles.td}>.p7b, .p7c</td>
            <td style={styles.td}>Base64 / Binary</td>
            <td style={styles.td}>{lang === 'sr' ? 'Sertifikati (chain)' : 'Certificates (chain)'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="warning">PKCS#12</Badge></td>
            <td style={styles.td}>.p12, .pfx</td>
            <td style={styles.td}>Binary</td>
            <td style={styles.td}>{lang === 'sr' ? 'Sertifikat + privatni ključ' : 'Certificate + private key'}</td>
          </tr>
        </tbody>
      </table>

      <div style={{ display: 'grid', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <InfoBox type="primary" title="PEM (Privacy Enhanced Mail)">
          <p style={{ marginBottom: '1rem' }}>
            {lang === 'sr'
              ? 'Najčešće korišćen format. Tekst format koji koristi Base64 enkodiranje.'
              : 'Most commonly used format. Text format that uses Base64 encoding.'}
          </p>
          <div style={{ background: 'var(--bg)', padding: '1rem', borderRadius: '6px', marginBottom: '1rem', border: '1px solid var(--border)' }}>
            <pre style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)', overflow: 'auto' }}>
{`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcz...
-----END CERTIFICATE-----`}
            </pre>
          </div>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li>{lang === 'sr' ? 'Može sadržati više sertifikata u jednom fajlu' : 'Can contain multiple certificates in one file'}</li>
            <li>{lang === 'sr' ? 'Lako se kopira i deli (tekst)' : 'Easy to copy and share (text)'}</li>
            <li>{lang === 'sr' ? 'Koristi se na Linux/Unix serverima' : 'Used on Linux/Unix servers'}</li>
            <li>{lang === 'sr' ? 'Apache, Nginx, OpenSSL koriste ovaj format' : 'Apache, Nginx, OpenSSL use this format'}</li>
          </ul>
        </InfoBox>

        <InfoBox type="success" title="DER (Distinguished Encoding Rules)">
          <p style={{ marginBottom: '1rem' }}>
            {lang === 'sr'
              ? 'Binarni format sertifikata. PEM je zapravo Base64-encoded DER.'
              : 'Binary certificate format. PEM is actually Base64-encoded DER.'}
          </p>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li>{lang === 'sr' ? 'Manji fajlovi od PEM' : 'Smaller files than PEM'}</li>
            <li>{lang === 'sr' ? 'Koristi se na Windows i Java platformama' : 'Used on Windows and Java platforms'}</li>
            <li>{lang === 'sr' ? 'Samo jedan sertifikat po fajlu' : 'Only one certificate per file'}</li>
            <li>{lang === 'sr' ? 'Nije čitljiv u text editoru' : 'Not readable in text editor'}</li>
          </ul>
          <div style={{ background: 'var(--bg)', padding: '0.75rem', borderRadius: '6px', marginTop: '1rem', border: '1px solid var(--border)' }}>
            <code style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {lang === 'sr' ? 'Konverzija:' : 'Conversion:'} openssl x509 -in cert.pem -outform DER -out cert.der
            </code>
          </div>
        </InfoBox>

        <InfoBox type="info" title="PKCS#7 / P7B (Cryptographic Message Syntax)">
          <p style={{ marginBottom: '1rem' }}>
            {lang === 'sr'
              ? 'Format za skladištenje sertifikata i certificate chain-a bez privatnog ključa.'
              : 'Format for storing certificates and certificate chains without the private key.'}
          </p>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li>{lang === 'sr' ? 'Sadrži samo sertifikate, NE privatne ključeve' : 'Contains only certificates, NOT private keys'}</li>
            <li>{lang === 'sr' ? 'Idealan za distribuciju CA chain-a' : 'Ideal for distributing CA chains'}</li>
            <li>{lang === 'sr' ? 'Podržan od Windows, IIS, Tomcat' : 'Supported by Windows, IIS, Tomcat'}</li>
            <li>{lang === 'sr' ? 'Koristi se za S/MIME email enkripciju' : 'Used for S/MIME email encryption'}</li>
          </ul>
          <div style={{ background: 'var(--bg)', padding: '0.75rem', borderRadius: '6px', marginTop: '1rem', border: '1px solid var(--border)' }}>
            <code style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {lang === 'sr' ? 'Kreiranje:' : 'Creating:'} openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b
            </code>
          </div>
        </InfoBox>

        <InfoBox type="warning" title="PKCS#12 / PFX (Personal Information Exchange)">
          <p style={{ marginBottom: '1rem' }}>
            {lang === 'sr'
              ? 'Binarni format koji sadrži sertifikat, privatni ključ i opciono chain. Zaštićen lozinkom.'
              : 'Binary format containing certificate, private key, and optionally chain. Password protected.'}
          </p>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li><strong>{lang === 'sr' ? 'VAŽNO:' : 'IMPORTANT:'}</strong> {lang === 'sr' ? 'Sadrži privatni ključ!' : 'Contains private key!'}</li>
            <li>{lang === 'sr' ? 'Uvek zaštićen lozinkom' : 'Always password protected'}</li>
            <li>{lang === 'sr' ? 'Koristi se za backup i prenos sertifikata' : 'Used for backup and certificate transfer'}</li>
            <li>{lang === 'sr' ? 'Windows, IIS, Tomcat, Java KeyStore' : 'Windows, IIS, Tomcat, Java KeyStore'}</li>
          </ul>
          <div style={{ background: 'var(--bg)', padding: '0.75rem', borderRadius: '6px', marginTop: '1rem', border: '1px solid var(--border)' }}>
            <code style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              openssl pkcs12 -export -in cert.pem -inkey key.pem -out cert.p12
            </code>
          </div>
        </InfoBox>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Koji format koristiti?' : 'Which format to use?'}</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{lang === 'sr' ? 'Scenario' : 'Scenario'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Preporučeni format' : 'Recommended format'}</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Apache/Nginx web server' : 'Apache/Nginx web server'}</td>
            <td style={styles.td}><Badge color="primary">PEM</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Windows IIS server' : 'Windows IIS server'}</td>
            <td style={styles.td}><Badge color="warning">PKCS#12 (.pfx)</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Java aplikacija (Tomcat)' : 'Java application (Tomcat)'}</td>
            <td style={styles.td}><Badge color="warning">PKCS#12</Badge> {lang === 'sr' ? 'ili' : 'or'} <Badge color="success">JKS</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Distribucija CA chain-a' : 'Distributing CA chain'}</td>
            <td style={styles.td}><Badge color="info">PKCS#7 (.p7b)</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Backup sertifikata sa ključem' : 'Certificate backup with key'}</td>
            <td style={styles.td}><Badge color="warning">PKCS#12 (.p12)</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>{lang === 'sr' ? 'Email (S/MIME)' : 'Email (S/MIME)'}</td>
            <td style={styles.td}><Badge color="warning">PKCS#12</Badge> {lang === 'sr' ? 'ili' : 'or'} <Badge color="info">PKCS#7</Badge></td>
          </tr>
        </tbody>
      </table>

      <InfoBox type="info" title={lang === 'sr' ? 'Korisne OpenSSL komande:' : 'Useful OpenSSL commands:'}>
        <div style={{ display: 'grid', gap: '0.75rem' }}>
          <div>
            <strong>{lang === 'sr' ? 'PEM → DER:' : 'PEM → DER:'}</strong>
            <pre style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>openssl x509 -in cert.pem -outform DER -out cert.der</pre>
          </div>
          <div>
            <strong>{lang === 'sr' ? 'DER → PEM:' : 'DER → PEM:'}</strong>
            <pre style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>openssl x509 -in cert.der -inform DER -out cert.pem</pre>
          </div>
          <div>
            <strong>{lang === 'sr' ? 'PEM → PKCS#12:' : 'PEM → PKCS#12:'}</strong>
            <pre style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>openssl pkcs12 -export -in cert.pem -inkey key.pem -out cert.p12</pre>
          </div>
          <div>
            <strong>{lang === 'sr' ? 'PKCS#12 → PEM:' : 'PKCS#12 → PEM:'}</strong>
            <pre style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>openssl pkcs12 -in cert.p12 -out cert.pem -nodes</pre>
          </div>
          <div>
            <strong>{lang === 'sr' ? 'Prikaz informacija o sertifikatu:' : 'View certificate info:'}</strong>
            <pre style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>openssl x509 -in cert.pem -text -noout</pre>
          </div>
        </div>
      </InfoBox>
    </div>
  )

  const renderCrypto = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{t('learn.crypto.title')}</h2>
      <p style={styles.paragraph}>{t('learn.crypto.intro')}</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <InfoBox type="primary" title="RSA">
          <p style={{ marginBottom: '1rem' }}>{t('learn.crypto.rsa.fullName')}</p>
          <h4 style={{ marginBottom: '0.5rem' }}>{t('learn.crypto.rsa.pros')}:</h4>
          <ul style={{ marginLeft: '1.25rem', marginBottom: '1rem' }}>
            {(lang === 'sr' ? ['Široka kompatibilnost', 'Dobro razumljen i testiran', 'Podržan svuda'] : ['Wide compatibility', 'Well understood and tested', 'Supported everywhere']).map((item, i) => (
              <li key={i} style={{ lineHeight: 1.6 }}>{item}</li>
            ))}
          </ul>
          <h4 style={{ marginBottom: '0.5rem' }}>{t('learn.crypto.rsa.cons')}:</h4>
          <ul style={{ marginLeft: '1.25rem' }}>
            {(lang === 'sr' ? ['Veći ključevi za istu sigurnost', 'Sporije operacije', 'Veći sertifikati'] : ['Larger keys for same security', 'Slower operations', 'Larger certificates']).map((item, i) => (
              <li key={i} style={{ lineHeight: 1.6 }}>{item}</li>
            ))}
          </ul>
        </InfoBox>

        <InfoBox type="success" title="ECC / ECDSA">
          <p style={{ marginBottom: '1rem' }}>{t('learn.crypto.ecc.fullName')}</p>
          <h4 style={{ marginBottom: '0.5rem' }}>{t('learn.crypto.ecc.pros')}:</h4>
          <ul style={{ marginLeft: '1.25rem', marginBottom: '1rem' }}>
            {(lang === 'sr' ? ['Manji ključevi za istu sigurnost', 'Brže operacije', 'Manja potrošnja resursa (idealno za IoT)'] : ['Smaller keys for same security', 'Faster operations', 'Lower resource consumption (ideal for IoT)']).map((item, i) => (
              <li key={i} style={{ lineHeight: 1.6 }}>{item}</li>
            ))}
          </ul>
          <h4 style={{ marginBottom: '0.5rem' }}>{t('learn.crypto.ecc.cons')}:</h4>
          <ul style={{ marginLeft: '1.25rem' }}>
            {(lang === 'sr' ? ['Nešto manja kompatibilnost sa legacy sistemima', 'Kompleksnija implementacija'] : ['Slightly less compatibility with legacy systems', 'More complex implementation']).map((item, i) => (
              <li key={i} style={{ lineHeight: 1.6 }}>{item}</li>
            ))}
          </ul>
        </InfoBox>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.crypto.comparison')}:</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{t('learn.crypto.securityLevel')}</th>
            <th style={styles.th}>RSA</th>
            <th style={styles.th}>ECC</th>
            <th style={styles.th}>{t('learn.crypto.ratio')}</th>
          </tr>
        </thead>
        <tbody>
          {[
            { bits: '80', rsa: '1024', ecc: '160', ratio: '6.4x' },
            { bits: '112', rsa: '2048', ecc: '224', ratio: '9.1x', badge: 'warning' },
            { bits: '128', rsa: '3072', ecc: '256 (P-256)', ratio: '12x', badge: 'success' },
            { bits: '192', rsa: '7680', ecc: '384 (P-384)', ratio: '20x', badge: 'info' },
            { bits: '256', rsa: '15360', ecc: '512 (P-521)', ratio: '30x', badge: 'primary' },
          ].map(row => (
            <tr key={row.bits}>
              <td style={styles.td}>{row.badge ? <Badge color={row.badge as any}>{row.bits} {lang === 'sr' ? 'bita' : 'bits'}</Badge> : `${row.bits} ${lang === 'sr' ? 'bita' : 'bits'}`}</td>
              <td style={styles.td}>{row.rsa} {lang === 'sr' ? 'bita' : 'bits'}</td>
              <td style={styles.td}>{row.ecc} {lang === 'sr' ? 'bita' : 'bits'}</td>
              <td style={styles.td}>{row.ratio} {lang === 'sr' ? 'manji' : 'smaller'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.crypto.popularCurves')}:</h3>
      <div style={{ display: 'grid', gap: '0.75rem', marginBottom: '1.5rem' }}>
        {[
          { name: 'P-256 (secp256r1 / prime256v1)', bits: '128-bit', desc: lang === 'sr' ? 'Najčešće korišćena, preporučena za većinu primena' : 'Most commonly used, recommended for most applications', badge: 'success' },
          { name: 'P-384 (secp384r1)', bits: '192-bit', desc: lang === 'sr' ? 'Za veću sigurnost, koriste je vladine agencije' : 'For higher security, used by government agencies', badge: 'info' },
          { name: 'P-521 (secp521r1)', bits: '256-bit', desc: lang === 'sr' ? 'Maksimalna sigurnost, retko potrebna' : 'Maximum security, rarely needed', badge: 'warning' },
          { name: 'Curve25519 / Ed25519', bits: '128-bit', desc: lang === 'sr' ? 'Moderna alternativa, popularna za SSH i signiranje' : 'Modern alternative, popular for SSH and signing', badge: 'primary' },
        ].map(curve => (
          <div key={curve.name} style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1rem', background: 'var(--bg)', borderRadius: '8px', border: '1px solid var(--border)' }}>
            <Badge color={curve.badge as any}>{curve.bits}</Badge>
            <div>
              <strong style={{ color: 'var(--text)' }}>{curve.name}</strong>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>{curve.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <InfoBox type="info" title={t('learn.crypto.recommendation') + ':'}>
        {t('learn.crypto.recommendationText')}
      </InfoBox>
    </div>
  )

  const renderKeysize = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{t('learn.keysize.title')}</h2>
      <p style={styles.paragraph}>{t('learn.keysize.intro')}</p>

      <div style={{ display: 'grid', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { size: 'RSA 2048', badge: t('learn.keysize.rsa2048.badge'), color: 'warning', items: [t('learn.keysize.rsa2048.security'), t('learn.keysize.rsa2048.performance'), t('learn.keysize.rsa2048.compatibility'), t('learn.keysize.rsa2048.recommendation')] },
          { size: 'RSA 3072', badge: t('learn.keysize.rsa3072.badge'), color: 'success', items: [t('learn.keysize.rsa3072.security'), t('learn.keysize.rsa3072.performance'), t('learn.keysize.rsa3072.compatibility'), t('learn.keysize.rsa3072.recommendation')] },
          { size: 'RSA 4096', badge: t('learn.keysize.rsa4096.badge'), color: 'primary', items: [t('learn.keysize.rsa4096.security'), t('learn.keysize.rsa4096.performance'), t('learn.keysize.rsa4096.compatibility'), t('learn.keysize.rsa4096.recommendation')] },
        ].map(item => (
          <div key={item.size} style={{ ...styles.infoBox, background: 'var(--bg)', border: `2px solid var(--${item.color})` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ color: `var(--${item.color})`, margin: 0 }}>{item.size}</h3>
              <Badge color={item.color as any}>{item.badge}</Badge>
            </div>
            <ul style={{ marginLeft: '1.25rem' }}>
              {item.items.map((text, i) => <li key={i} style={styles.listItem}>{text}</li>)}
            </ul>
          </div>
        ))}
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.keysize.benchmarkTitle')}:</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{t('learn.keysize.operation')}</th>
            <th style={styles.th}>RSA 2048</th>
            <th style={styles.th}>RSA 3072</th>
            <th style={styles.th}>RSA 4096</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}>{t('learn.keysize.keyGeneration')}</td>
            <td style={styles.td}>1x {t('learn.keysize.base')}</td>
            <td style={styles.td}>~3x {t('learn.keysize.slower')}</td>
            <td style={styles.td}>~8x {t('learn.keysize.slower')}</td>
          </tr>
          <tr>
            <td style={styles.td}>{t('learn.keysize.signing')}</td>
            <td style={styles.td}>1x</td>
            <td style={styles.td}>~2.5x {t('learn.keysize.slower')}</td>
            <td style={styles.td}>~6x {t('learn.keysize.slower')}</td>
          </tr>
          <tr>
            <td style={styles.td}>{t('learn.keysize.verification')}</td>
            <td style={styles.td}>1x</td>
            <td style={styles.td}>~1.5x {t('learn.keysize.slower')}</td>
            <td style={styles.td}>~2x {t('learn.keysize.slower')}</td>
          </tr>
          <tr>
            <td style={styles.td}>{t('learn.keysize.signatureSize')}</td>
            <td style={styles.td}>256 {t('learn.keysize.bytes')}</td>
            <td style={styles.td}>384 {t('learn.keysize.bytes')}</td>
            <td style={styles.td}>512 {t('learn.keysize.bytes')}</td>
          </tr>
        </tbody>
      </table>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.keysize.recommendationsTitle')}:</h3>
      <div style={{ display: 'grid', gap: '0.75rem', marginBottom: '1.5rem' }}>
        {[
          { type: 'Root CA', key: 'RSA 4096 / ECC P-384', reason: lang === 'sr' ? 'Dugotrajni (20+ godina), sigurnost prioritet' : 'Long-lived (20+ years), security priority', badge: 'primary' },
          { type: 'Intermediate CA', key: 'RSA 4096 / ECC P-256', reason: lang === 'sr' ? 'Srednjeročni (5-10 godina)' : 'Medium-term (5-10 years)', badge: 'success' },
          { type: 'Server/TLS', key: 'RSA 2048/3072 / ECC P-256', reason: lang === 'sr' ? 'Kratkoročni (1-2 godine), performanse bitne' : 'Short-term (1-2 years), performance matters', badge: 'info' },
          { type: 'Client/Email', key: 'RSA 2048 / ECC P-256', reason: lang === 'sr' ? 'Kratkoročni, kompatibilnost bitna' : 'Short-term, compatibility matters', badge: 'warning' },
        ].map(item => (
          <div key={item.type} style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1rem', background: 'var(--bg)', borderRadius: '8px', border: '1px solid var(--border)' }}>
            <Badge color={item.badge as any}>{item.type}</Badge>
            <div>
              <strong style={{ color: 'var(--text)' }}>{item.key}</strong>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>{item.reason}</p>
            </div>
          </div>
        ))}
      </div>

      <InfoBox type="warning" title={t('learn.keysize.nistTitle') + ':'}>
        {t('learn.keysize.nistText')}
      </InfoBox>
    </div>
  )

  const renderHash = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{t('learn.hash.title')}</h2>
      <p style={styles.paragraph}>{t('learn.hash.intro')}</p>

      <div style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)', marginBottom: '1.5rem' }}>
        <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.hash.howUsedTitle')}</h3>
        <div style={{ position: 'relative', paddingLeft: '2rem' }}>
          <div style={{ position: 'absolute', left: '0.5rem', top: 0, bottom: 0, width: '2px', background: 'var(--border)' }} />
          {(lang === 'sr'
            ? ['CA uzima sadržaj sertifikata (ime, javni ključ, rok...)', 'Primenjuje SHA algoritam da dobije hash (npr. 256 bita)', 'Potpisuje taj hash svojim privatnim ključem', 'Potpis se dodaje sertifikatu']
            : ['CA takes the certificate content (name, public key, expiry...)', 'Applies SHA algorithm to get a hash (e.g., 256 bits)', 'Signs that hash with its private key', 'The signature is added to the certificate']
          ).map((text, i) => (
            <div key={i} style={{ marginBottom: '1rem', position: 'relative' }}>
              <div style={{
                position: 'absolute',
                left: '-1.75rem',
                width: '1.5rem',
                height: '1.5rem',
                borderRadius: '50%',
                background: 'var(--primary)',
                color: 'white',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.75rem',
                fontWeight: 'bold'
              }}>
                {i + 1}
              </div>
              <p style={{ fontSize: '0.925rem', color: 'var(--text)' }}>{text}</p>
            </div>
          ))}
        </div>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.hash.versionsTitle')}:</h3>
      <div style={{ display: 'grid', gap: '1rem', marginBottom: '1.5rem' }}>
        <InfoBox type="danger" title="SHA-1 (160 bits)">
          <div style={{ marginBottom: '0.5rem' }}><Badge color="danger">{t('learn.hash.sha1.status')}</Badge></div>
          {t('learn.hash.sha1.desc')}
        </InfoBox>

        <InfoBox type="success" title="SHA-256 (256 bits)">
          <div style={{ marginBottom: '0.5rem' }}><Badge color="success">{t('learn.hash.sha256.status')}</Badge></div>
          <p style={{ marginBottom: '0.75rem' }}>{t('learn.hash.sha256.desc')}</p>
          <code style={{ fontSize: '0.75rem', background: 'var(--bg)', padding: '0.25rem 0.5rem', borderRadius: '4px', display: 'block', overflowX: 'auto', color: 'var(--text)' }}>
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
          </code>
        </InfoBox>

        <InfoBox type="info" title="SHA-384 (384 bits)">
          <div style={{ marginBottom: '0.5rem' }}><Badge color="info">{t('learn.hash.sha384.status')}</Badge></div>
          {t('learn.hash.sha384.desc')}
        </InfoBox>

        <InfoBox type="primary" title="SHA-512 (512 bits)">
          <div style={{ marginBottom: '0.5rem' }}><Badge color="primary">{t('learn.hash.sha512.status')}</Badge></div>
          {t('learn.hash.sha512.desc')}
        </InfoBox>

        <div style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '0.75rem', color: 'var(--text)' }}>SHA-3 (224/256/384/512 bits)</h4>
          <div style={{ marginBottom: '0.5rem' }}><Badge color="info">{t('learn.hash.sha3.status')}</Badge></div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.925rem' }}>{t('learn.hash.sha3.desc')}</p>
        </div>
      </div>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{t('learn.hash.comparisonTitle')}:</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{t('learn.hash.algorithm')}</th>
            <th style={styles.th}>{t('learn.hash.output')}</th>
            <th style={styles.th}>{t('learn.hash.security')}</th>
            <th style={styles.th}>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}>MD5</td>
            <td style={styles.td}>128 bits</td>
            <td style={styles.td}>{t('learn.hash.broken')}</td>
            <td style={styles.td}><Badge color="danger">{t('learn.hash.forbidden')}</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>SHA-1</td>
            <td style={styles.td}>160 bits</td>
            <td style={styles.td}>{t('learn.hash.broken')}</td>
            <td style={styles.td}><Badge color="danger">{t('learn.hash.forbidden')}</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>SHA-256</td>
            <td style={styles.td}>256 bits</td>
            <td style={styles.td}>128-bit</td>
            <td style={styles.td}><Badge color="success">{t('learn.hash.recommended')}</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>SHA-384</td>
            <td style={styles.td}>384 bits</td>
            <td style={styles.td}>192-bit</td>
            <td style={styles.td}><Badge color="info">{t('learn.hash.secure')}</Badge></td>
          </tr>
          <tr>
            <td style={styles.td}>SHA-512</td>
            <td style={styles.td}>512 bits</td>
            <td style={styles.td}>256-bit</td>
            <td style={styles.td}><Badge color="info">{t('learn.hash.secure')}</Badge></td>
          </tr>
        </tbody>
      </table>

      <InfoBox type="success" title={t('learn.hash.combinationsTitle') + ':'}>
        <p style={{ marginBottom: '0.5rem' }}>{t('learn.hash.combinationsIntro')}</p>
        <ul style={{ marginLeft: '1.25rem' }}>
          <li><code style={{ color: 'var(--text)' }}>sha256WithRSAEncryption</code> - SHA-256 + RSA</li>
          <li><code style={{ color: 'var(--text)' }}>ecdsa-with-SHA256</code> - SHA-256 + ECDSA</li>
          <li><code style={{ color: 'var(--text)' }}>sha384WithRSAEncryption</code> - SHA-384 + RSA</li>
          <li><code style={{ color: 'var(--text)' }}>ecdsa-with-SHA384</code> - SHA-384 + ECDSA</li>
        </ul>
      </InfoBox>
    </div>
  )

  const renderRenewal = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Obnova sertifikata (Renewal)' : 'Certificate Renewal'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Svi sertifikati imaju rok trajanja. Kada sertifikat istekne, više nije validan i mora se zameniti novim. Proces obnove zavisi od tipa sertifikata.'
          : 'All certificates have an expiration date. When a certificate expires, it is no longer valid and must be replaced with a new one. The renewal process depends on the certificate type.'}
      </p>

      <InfoBox type="warning" title={lang === 'sr' ? 'Zašto sertifikati ističu?' : 'Why do certificates expire?'}>
        <ul style={{ marginLeft: '1.25rem' }}>
          <li>{lang === 'sr' ? 'Ograničava štetu ako je privatni ključ kompromitovan' : 'Limits damage if the private key is compromised'}</li>
          <li>{lang === 'sr' ? 'Forsira redovnu proveru i ažuriranje' : 'Forces regular verification and updates'}</li>
          <li>{lang === 'sr' ? 'Omogućava primenu novih kriptografskih standarda' : 'Enables adoption of new cryptographic standards'}</li>
        </ul>
      </InfoBox>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Tipična trajanja sertifikata:' : 'Typical certificate lifespans:'}</h3>
      <table style={{ ...styles.table, marginBottom: '1.5rem' }}>
        <thead>
          <tr>
            <th style={styles.th}>{lang === 'sr' ? 'Tip' : 'Type'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Trajanje' : 'Duration'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Razlog' : 'Reason'}</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}><Badge color="info">Root CA</Badge></td>
            <td style={styles.td}>20-30 {lang === 'sr' ? 'godina' : 'years'}</td>
            <td style={styles.td}>{lang === 'sr' ? 'Teško za zamenu, ugrađen u OS/browser' : 'Hard to replace, built into OS/browser'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="success">Intermediate CA</Badge></td>
            <td style={styles.td}>5-10 {lang === 'sr' ? 'godina' : 'years'}</td>
            <td style={styles.td}>{lang === 'sr' ? 'Lakše za zamenu od Root CA' : 'Easier to replace than Root CA'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="warning">Server/Client</Badge></td>
            <td style={styles.td}>1-2 {lang === 'sr' ? 'godine (max 398 dana za javne)' : 'years (max 398 days for public)'}</td>
            <td style={styles.td}>{lang === 'sr' ? 'Česta rotacija za bolju sigurnost' : 'Frequent rotation for better security'}</td>
          </tr>
        </tbody>
      </table>

      <InfoBox type="info" title={lang === 'sr' ? 'Automatska obnova:' : 'Automatic renewal:'}>
        {lang === 'sr'
          ? "Moderni sistemi kao ACME protokol (koristi Let's Encrypt) omogućavaju potpuno automatsku obnovu sertifikata. Certbot i slični alati mogu automatski obnoviti sertifikat pre isteka bez ručne intervencije."
          : "Modern systems like the ACME protocol (used by Let's Encrypt) enable fully automatic certificate renewal. Certbot and similar tools can automatically renew certificates before expiration without manual intervention."}
      </InfoBox>
    </div>
  )

  const renderExpiry = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Istek Root CA i Intermediate CA' : 'Root CA and Intermediate CA Expiry'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Istek CA sertifikata je ozbiljan događaj koji zahteva pažljivo planiranje. Kada CA istekne, svi sertifikati koje je izdao postaju nevažeći.'
          : 'CA certificate expiry is a serious event that requires careful planning. When a CA expires, all certificates it issued become invalid.'}
      </p>

      <InfoBox type="danger" title={lang === 'sr' ? 'UPOZORENJE' : 'WARNING'}>
        {lang === 'sr'
          ? 'Ako Root CA istekne, SVI sertifikati u hijerarhiji (Intermediate CA + svi krajnji sertifikati) postaju nevažeći istog trenutka, čak i ako im individualni rok nije istekao!'
          : 'If the Root CA expires, ALL certificates in the hierarchy (Intermediate CA + all end certificates) become invalid at the same moment, even if their individual expiration has not passed!'}
      </InfoBox>

      <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{lang === 'sr' ? 'Vremenska linija planiranja:' : 'Planning timeline:'}</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>{lang === 'sr' ? 'Vreme do isteka' : 'Time to expiry'}</th>
            <th style={styles.th}>{lang === 'sr' ? 'Akcija' : 'Action'}</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={styles.td}><Badge color="success">5+ {lang === 'sr' ? 'godina' : 'years'}</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Planiraj strategiju, dokumentuj proces' : 'Plan strategy, document process'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="info">2-5 {lang === 'sr' ? 'godina' : 'years'}</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Kreiraj novi CA, počni cross-signing ili distribuciju' : 'Create new CA, start cross-signing or distribution'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="warning">1-2 {lang === 'sr' ? 'godine' : 'years'}</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Aktivno zamenjuj sertifikate, testiraj sa novim CA' : 'Actively replace certificates, test with new CA'}</td>
          </tr>
          <tr>
            <td style={styles.td}><Badge color="danger">&lt; 1 {lang === 'sr' ? 'godina' : 'year'}</Badge></td>
            <td style={styles.td}>{lang === 'sr' ? 'Hitna zamena svih preostalih sertifikata' : 'Emergency replacement of all remaining certificates'}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )

  const renderBest = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Best Practices za sertifikate' : 'Certificate Best Practices'}</h2>
      <p style={styles.paragraph}>
        {lang === 'sr'
          ? 'Pravilno upravljanje sertifikatima je ključno za sigurnost vaše infrastrukture.'
          : 'Proper certificate management is crucial for the security of your infrastructure.'}
      </p>

      <div style={{ display: 'grid', gap: '1.5rem' }}>
        <InfoBox type="primary" title={lang === 'sr' ? 'Upravljanje ključevima' : 'Key Management'}>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li><strong>{lang === 'sr' ? 'Nikad ne delite privatne ključeve' : 'Never share private keys'}</strong> - {lang === 'sr' ? 'svaki server/korisnik ima svoj ključ' : 'each server/user has their own key'}</li>
            <li><strong>{lang === 'sr' ? 'Čuvajte Root CA offline' : 'Keep Root CA offline'}</strong> - {lang === 'sr' ? 'u HSM ili air-gapped sistemu' : 'in HSM or air-gapped system'}</li>
            <li><strong>{lang === 'sr' ? 'Koristite jake lozinke' : 'Use strong passwords'}</strong> - {lang === 'sr' ? 'za zaštitu privatnih ključeva' : 'to protect private keys'}</li>
            <li><strong>{lang === 'sr' ? 'Redovno rotirajte ključeve' : 'Regularly rotate keys'}</strong> - {lang === 'sr' ? 'posebno za krajnje sertifikate' : 'especially for end certificates'}</li>
          </ul>
        </InfoBox>

        <InfoBox type="success" title={lang === 'sr' ? 'Kriptografski izbori' : 'Cryptographic Choices'}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>{lang === 'sr' ? 'Komponenta' : 'Component'}</th>
                <th style={styles.th}>{lang === 'sr' ? 'Preporuka 2024+' : '2024+ Recommendation'}</th>
                <th style={styles.th}>{lang === 'sr' ? 'Izbegavati' : 'Avoid'}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={styles.td}>{lang === 'sr' ? 'Algoritam' : 'Algorithm'}</td>
                <td style={styles.td}><Badge color="success">ECC P-256</Badge> / <Badge color="info">RSA 3072+</Badge></td>
                <td style={styles.td}><Badge color="danger">RSA 1024</Badge></td>
              </tr>
              <tr>
                <td style={styles.td}>Hash</td>
                <td style={styles.td}><Badge color="success">SHA-256</Badge> / <Badge color="info">SHA-384</Badge></td>
                <td style={styles.td}><Badge color="danger">SHA-1, MD5</Badge></td>
              </tr>
              <tr>
                <td style={styles.td}>TLS</td>
                <td style={styles.td}><Badge color="success">TLS 1.3</Badge> / <Badge color="info">TLS 1.2</Badge></td>
                <td style={styles.td}><Badge color="danger">TLS 1.0/1.1, SSL</Badge></td>
              </tr>
            </tbody>
          </table>
        </InfoBox>

        <InfoBox type="warning" title={lang === 'sr' ? 'Životni ciklus sertifikata' : 'Certificate Lifecycle'}>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li><strong>{lang === 'sr' ? 'Postavi monitoring' : 'Set up monitoring'}</strong> - {lang === 'sr' ? 'alertovi 90, 60, 30, 14, 7 dana pre isteka' : 'alerts 90, 60, 30, 14, 7 days before expiry'}</li>
            <li><strong>{lang === 'sr' ? 'Automatizuj obnovu' : 'Automate renewal'}</strong> - ACME/Certbot {lang === 'sr' ? 'za javne, skripte za interne' : 'for public, scripts for internal'}</li>
            <li><strong>{lang === 'sr' ? 'Dokumentuj sve' : 'Document everything'}</strong> - {lang === 'sr' ? 'ko je izdao, zašto, gde se koristi' : 'who issued it, why, where it\'s used'}</li>
            <li><strong>{lang === 'sr' ? 'Kratko trajanje' : 'Short validity'}</strong> - {lang === 'sr' ? 'maksimum 398 dana za TLS' : 'maximum 398 days for TLS'}</li>
          </ul>
        </InfoBox>

        <InfoBox type="info" title={lang === 'sr' ? 'Korisni alati za testiranje:' : 'Useful testing tools:'}>
          <ul style={{ marginLeft: '1.25rem' }}>
            <li><strong>SSL Labs</strong> (ssllabs.com) - {lang === 'sr' ? 'testira konfiguraciju TLS servera' : 'tests TLS server configuration'}</li>
            <li><strong>openssl s_client</strong> - {lang === 'sr' ? 'komandna linija za debug' : 'command line for debugging'}</li>
            <li><strong>testssl.sh</strong> - {lang === 'sr' ? 'skripta za temeljno testiranje' : 'script for thorough testing'}</li>
          </ul>
        </InfoBox>
      </div>
    </div>
  )

  const renderExamples = () => (
    <div style={styles.card}>
      <h2 style={styles.sectionTitle}>{lang === 'sr' ? 'Primeri iz prakse' : 'Real-world Examples'}</h2>

      <div style={{ display: 'grid', gap: '1.5rem' }}>
        {[
          {
            icon: 'building',
            title: lang === 'sr' ? 'Online bankarstvo' : 'Online Banking',
            desc: lang === 'sr'
              ? 'Kada pristupate online banci, server sertifikat garantuje da komunicirate sa pravom bankom, a ne sa lažnim sajtom.'
              : 'When accessing online banking, the server certificate guarantees you are communicating with the real bank, not a fake site.',
            badges: ['HTTPS', 'EV Certificate', '2FA'],
          },
          {
            icon: 'office',
            title: lang === 'sr' ? 'Korporativna mreža' : 'Corporate Network',
            desc: lang === 'sr'
              ? 'Kompanija ima svoj Root CA i izdaje sertifikate zaposlenima. Samo uređaji sa validnim sertifikatom mogu pristupiti internoj mreži.'
              : 'A company has its own Root CA and issues certificates to employees. Only devices with valid certificates can access the internal network.',
            badges: ['Internal CA', 'mTLS', 'VPN'],
          },
          {
            icon: 'cloud',
            title: lang === 'sr' ? 'Mikroservisi (Kubernetes)' : 'Microservices (Kubernetes)',
            desc: lang === 'sr'
              ? 'U cloud okruženju, svaki mikroservis ima svoj sertifikat. Servisi komuniciraju koristeći mTLS.'
              : 'In a cloud environment, each microservice has its own certificate. Services communicate using mTLS.',
            badges: ['mTLS', 'Service Mesh', 'Zero Trust'],
          },
          {
            icon: 'mail',
            title: lang === 'sr' ? 'Email potpisivanje' : 'Email Signing',
            desc: lang === 'sr'
              ? 'S/MIME sertifikati omogućavaju digitalno potpisivanje i šifrovanje emailova.'
              : 'S/MIME certificates enable digital signing and encryption of emails.',
            badges: ['S/MIME', 'Digital Signature', 'E2E Encryption'],
          },
        ].map(item => (
          <div key={item.title} style={{ ...styles.infoBox, background: 'var(--bg)', border: '1px solid var(--border)' }}>
            <h3 style={{ marginBottom: '1rem', color: 'var(--text)' }}>{item.title}</h3>
            <p style={{ marginBottom: '1rem', lineHeight: 1.8, color: 'var(--text)' }}>{item.desc}</p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {item.badges.map(b => <Badge key={b} color="info">{b}</Badge>)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const renderSection = () => {
    switch (activeSection) {
      case 'intro': return renderIntro()
      case 'how': return renderHow()
      case 'root': return renderRoot()
      case 'intermediate': return renderIntermediate()
      case 'server': return renderServer()
      case 'client': return renderClient()
      case 'ssl': return renderSsl()
      case 'formats': return renderFormats()
      case 'crypto': return renderCrypto()
      case 'keysize': return renderKeysize()
      case 'hash': return renderHash()
      case 'renewal': return renderRenewal()
      case 'expiry': return renderExpiry()
      case 'best': return renderBest()
      case 'examples': return renderExamples()
      default: return renderIntro()
    }
  }

  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem', color: 'var(--text)' }}>{t('learn.title')}</h1>

      <div style={{ display: 'flex', gap: '2rem', alignItems: 'flex-start' }}>
        <nav style={{
          minWidth: '220px',
          position: 'sticky',
          top: '1rem',
          background: 'var(--card-bg)',
          borderRadius: '8px',
          border: '1px solid var(--border)',
          padding: '0.5rem',
        }}>
          {sections.map(section => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              style={{
                display: 'block',
                width: '100%',
                padding: '0.75rem 1rem',
                border: 'none',
                background: activeSection === section.id ? 'var(--primary)' : 'transparent',
                color: activeSection === section.id ? 'white' : 'var(--text)',
                borderRadius: '6px',
                textAlign: 'left',
                cursor: 'pointer',
                fontSize: '0.875rem',
                marginBottom: '0.25rem',
                fontWeight: activeSection === section.id ? 600 : 400,
                transition: 'all 0.15s ease',
              }}
            >
              {section.title}
            </button>
          ))}
        </nav>

        <div style={{ flex: 1 }}>
          {renderSection()}
        </div>
      </div>
    </div>
  )
}

export default Learn
