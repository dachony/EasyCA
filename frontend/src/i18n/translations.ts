export type Language = 'sr' | 'en'

export const translations = {
  // Navigation
  nav: {
    dashboard: { sr: 'Kontrolna tabla', en: 'Dashboard' },
    cas: { sr: 'Sertifikaciona tela', en: 'Certificate Authorities' },
    certificates: { sr: 'Sertifikati', en: 'Certificates' },
    csrs: { sr: 'CSR zahtevi', en: 'CSRs' },
    tools: { sr: 'Alati', en: 'Tools' },
    learn: { sr: 'Edukacija', en: 'Learn' },
    audit: { sr: 'Revizijski log', en: 'Audit Log' },
    settings: { sr: 'Podešavanja', en: 'Settings' },
  },

  // Common
  common: {
    save: { sr: 'Sačuvaj', en: 'Save' },
    cancel: { sr: 'Otkaži', en: 'Cancel' },
    delete: { sr: 'Obriši', en: 'Delete' },
    create: { sr: 'Kreiraj', en: 'Create' },
    download: { sr: 'Preuzmi', en: 'Download' },
    loading: { sr: 'Učitavanje...', en: 'Loading...' },
    actions: { sr: 'Akcije', en: 'Actions' },
    name: { sr: 'Naziv', en: 'Name' },
    type: { sr: 'Tip', en: 'Type' },
    status: { sr: 'Status', en: 'Status' },
    validFrom: { sr: 'Važi od', en: 'Valid From' },
    validUntil: { sr: 'Važi do', en: 'Valid Until' },
    created: { sr: 'Kreirano', en: 'Created' },
    yes: { sr: 'Da', en: 'Yes' },
    no: { sr: 'Ne', en: 'No' },
  },

  // Learn page sections
  learn: {
    title: { sr: 'Naučite o sertifikatima', en: 'Learn about certificates' },
    sections: {
      intro: { sr: 'Šta su sertifikati?', en: 'What are certificates?' },
      how: { sr: 'Kako funkcionišu?', en: 'How do they work?' },
      root: { sr: 'Root CA', en: 'Root CA' },
      intermediate: { sr: 'Intermediate CA', en: 'Intermediate CA' },
      server: { sr: 'Server sertifikati', en: 'Server certificates' },
      client: { sr: 'Client sertifikati', en: 'Client certificates' },
      crypto: { sr: 'RSA vs ECC', en: 'RSA vs ECC' },
      keysize: { sr: 'Veličine ključeva', en: 'Key sizes' },
      hash: { sr: 'SHA algoritmi', en: 'SHA algorithms' },
      renewal: { sr: 'Obnova sertifikata', en: 'Certificate renewal' },
      expiry: { sr: 'Istek CA sertifikata', en: 'CA certificate expiry' },
      best: { sr: 'Najbolje prakse', en: 'Best Practices' },
      examples: { sr: 'Primeri korišćenja', en: 'Usage examples' },
      ssl: { sr: 'SSL/TLS protokoli', en: 'SSL/TLS Protocols' },
      formats: { sr: 'Formati sertifikata', en: 'Certificate Formats' },
    },

    // Intro section
    intro: {
      title: { sr: 'Šta su digitalni sertifikati?', en: 'What are digital certificates?' },
      p1: {
        sr: 'Zamislite digitalni sertifikat kao ličnu kartu na internetu. Baš kao što lična karta potvrđuje vaš identitet u stvarnom svetu, digitalni sertifikat potvrđuje identitet web sajta, servera ili korisnika na internetu.',
        en: 'Think of a digital certificate as an ID card on the internet. Just as an ID card confirms your identity in the real world, a digital certificate confirms the identity of a website, server, or user on the internet.'
      },
      analogyTitle: { sr: 'Analogija sa stvarnim svetom', en: 'Real world analogy' },
      analogyP1: {
        sr: 'Kada idete u banku, službenik traži ličnu kartu da potvrdi da ste vi zaista vi. Tu ličnu kartu je izdalo MUP (poverljiva institucija), i banka veruje MUP-u.',
        en: 'When you go to a bank, the clerk asks for ID to confirm you are who you say you are. That ID was issued by a government agency (trusted institution), and the bank trusts that agency.'
      },
      analogyP2: {
        sr: 'Na isti način, kada vaš browser poseti web sajt (npr. banku), sajt pokazuje svoj digitalni sertifikat. Taj sertifikat je izdao Certificate Authority (CA) - poverljiva organizacija kojoj browser veruje.',
        en: 'Similarly, when your browser visits a website (e.g., a bank), the site shows its digital certificate. That certificate was issued by a Certificate Authority (CA) - a trusted organization that the browser trusts.'
      },
      contentsTitle: { sr: 'Šta sertifikat sadrži?', en: 'What does a certificate contain?' },
      contents: {
        owner: { sr: 'Ime vlasnika - ko poseduje sertifikat (npr. "google.com")', en: 'Owner name - who owns the certificate (e.g., "google.com")' },
        publicKey: { sr: 'Javni ključ - koristi se za šifrovanje podataka', en: 'Public key - used for encrypting data' },
        issuer: { sr: 'Ko ga je izdao - Certificate Authority koji garantuje identitet', en: 'Issuer - Certificate Authority that guarantees the identity' },
        validity: { sr: 'Rok važenja - od kada do kada važi', en: 'Validity period - when it\'s valid from and until' },
        signature: { sr: 'Digitalni potpis - dokaz da nije falsifikovan', en: 'Digital signature - proof it hasn\'t been forged' },
      },
    },

    // Crypto section
    crypto: {
      title: { sr: 'RSA vs ECC (Elliptic Curve Cryptography)', en: 'RSA vs ECC (Elliptic Curve Cryptography)' },
      intro: {
        sr: 'Postoje dva glavna tipa asimetrične kriptografije koji se koriste za sertifikate: RSA i ECC (Elliptic Curve Cryptography).',
        en: 'There are two main types of asymmetric cryptography used for certificates: RSA and ECC (Elliptic Curve Cryptography).'
      },
      rsa: {
        name: 'RSA',
        fullName: { sr: 'Rivest-Shamir-Adleman - Najstariji i najrasprostranjeniji algoritam (1977). Zasnovan na teškoći faktorizacije velikih prostih brojeva.', en: 'Rivest-Shamir-Adleman - The oldest and most widespread algorithm (1977). Based on the difficulty of factoring large prime numbers.' },
        pros: { sr: 'Prednosti', en: 'Advantages' },
        prosList: {
          sr: ['Široka kompatibilnost', 'Dobro razumljen i testiran', 'Podržan svuda'],
          en: ['Wide compatibility', 'Well understood and tested', 'Supported everywhere']
        },
        cons: { sr: 'Mane', en: 'Disadvantages' },
        consList: {
          sr: ['Veći ključevi za istu sigurnost', 'Sporije operacije', 'Veći sertifikati'],
          en: ['Larger keys for same security', 'Slower operations', 'Larger certificates']
        },
      },
      ecc: {
        name: 'ECC / ECDSA',
        fullName: { sr: 'Elliptic Curve Digital Signature Algorithm - Moderniji pristup (1985/2005). Zasnovan na teškoći problema diskretnog logaritma na eliptičkim krivama.', en: 'Elliptic Curve Digital Signature Algorithm - Modern approach (1985/2005). Based on the difficulty of the discrete logarithm problem on elliptic curves.' },
        pros: { sr: 'Prednosti', en: 'Advantages' },
        prosList: {
          sr: ['Manji ključevi za istu sigurnost', 'Brže operacije', 'Manja potrošnja resursa (idealno za IoT)'],
          en: ['Smaller keys for same security', 'Faster operations', 'Lower resource consumption (ideal for IoT)']
        },
        cons: { sr: 'Mane', en: 'Disadvantages' },
        consList: {
          sr: ['Nešto manja kompatibilnost sa legacy sistemima', 'Kompleksnija implementacija'],
          en: ['Slightly less compatibility with legacy systems', 'More complex implementation']
        },
      },
      comparison: { sr: 'Upoređenje ekvivalentne sigurnosti', en: 'Equivalent security comparison' },
      securityLevel: { sr: 'Nivo sigurnosti', en: 'Security level' },
      ratio: { sr: 'Odnos', en: 'Ratio' },
      popularCurves: { sr: 'Popularne ECC krive', en: 'Popular ECC curves' },
      recommendation: { sr: 'Preporuka', en: 'Recommendation' },
      recommendationText: {
        sr: 'Za nove implementacije, ECC P-256 je odličan izbor za većinu slučajeva. Ako vam je potrebna maksimalna kompatibilnost sa starijim sistemima, koristite RSA 2048 ili RSA 3072.',
        en: 'For new implementations, ECC P-256 is an excellent choice for most cases. If you need maximum compatibility with older systems, use RSA 2048 or RSA 3072.'
      },
    },

    // Key size section
    keysize: {
      title: { sr: 'Veličine RSA ključeva: 2048, 3072, 4096', en: 'RSA key sizes: 2048, 3072, 4096' },
      intro: {
        sr: 'Veličina RSA ključa direktno utiče na sigurnost i performanse. Veći ključ = veća sigurnost, ali i sporije operacije.',
        en: 'RSA key size directly affects security and performance. Larger key = more security, but slower operations.'
      },
      rsa2048: {
        badge: { sr: 'Minimalni standard', en: 'Minimum standard' },
        security: { sr: 'Sigurnost: ~112 bita (siguran do ~2030)', en: 'Security: ~112 bits (secure until ~2030)' },
        performance: { sr: 'Performanse: Najbrži od tri opcije', en: 'Performance: Fastest of the three options' },
        compatibility: { sr: 'Kompatibilnost: Univerzalna', en: 'Compatibility: Universal' },
        recommendation: { sr: 'Preporuka: OK za kratkoročne sertifikate (1-2 godine)', en: 'Recommendation: OK for short-term certificates (1-2 years)' },
      },
      rsa3072: {
        badge: { sr: 'Preporučeno', en: 'Recommended' },
        security: { sr: 'Sigurnost: ~128 bita (siguran do ~2030+)', en: 'Security: ~128 bits (secure until ~2030+)' },
        performance: { sr: 'Performanse: ~2x sporiji od 2048', en: 'Performance: ~2x slower than 2048' },
        compatibility: { sr: 'Kompatibilnost: Vrlo dobra', en: 'Compatibility: Very good' },
        recommendation: { sr: 'Preporuka: Idealan balans sigurnosti i performansi', en: 'Recommendation: Ideal balance of security and performance' },
      },
      rsa4096: {
        badge: { sr: 'Maksimalna sigurnost', en: 'Maximum security' },
        security: { sr: 'Sigurnost: ~140 bita (siguran dugoročno)', en: 'Security: ~140 bits (secure long-term)' },
        performance: { sr: 'Performanse: ~4-7x sporiji od 2048', en: 'Performance: ~4-7x slower than 2048' },
        compatibility: { sr: 'Kompatibilnost: Dobra (neki legacy sistemi imaju probleme)', en: 'Compatibility: Good (some legacy systems have issues)' },
        recommendation: { sr: 'Preporuka: Za Root CA i dugotrajne sertifikate', en: 'Recommendation: For Root CA and long-lived certificates' },
      },
      benchmarkTitle: { sr: 'Benchmark performansi (relativno)', en: 'Performance benchmark (relative)' },
      operation: { sr: 'Operacija', en: 'Operation' },
      keyGeneration: { sr: 'Generisanje ključa', en: 'Key generation' },
      signing: { sr: 'Potpisivanje', en: 'Signing' },
      verification: { sr: 'Verifikacija', en: 'Verification' },
      signatureSize: { sr: 'Veličina potpisa', en: 'Signature size' },
      base: { sr: '(bazno)', en: '(base)' },
      slower: { sr: 'sporije', en: 'slower' },
      bytes: { sr: 'bajtova', en: 'bytes' },
      recommendationsTitle: { sr: 'Preporuke po tipu sertifikata', en: 'Recommendations by certificate type' },
      nistTitle: { sr: 'NIST preporuke (2020+)', en: 'NIST recommendations (2020+)' },
      nistText: {
        sr: 'NIST preporučuje minimum RSA 2048 do 2030. godine, a nakon toga prelazak na RSA 3072 ili ECC P-256. Za dugoročnu sigurnost (post-kvantna era), razmislite o ECC ili hibridnim rešenjima.',
        en: 'NIST recommends minimum RSA 2048 until 2030, then transition to RSA 3072 or ECC P-256. For long-term security (post-quantum era), consider ECC or hybrid solutions.'
      },
    },

    // Hash section
    hash: {
      title: { sr: 'SHA algoritmi za hash funkcije', en: 'SHA algorithms for hash functions' },
      intro: {
        sr: 'SHA (Secure Hash Algorithm) se koristi za kreiranje digitalnog potpisa sertifikata. Hash funkcija pretvara podatke bilo koje veličine u fiksni "otisak prsta" koji je jedinstven za te podatke.',
        en: 'SHA (Secure Hash Algorithm) is used to create the digital signature of certificates. A hash function converts data of any size into a fixed "fingerprint" that is unique to that data.'
      },
      howUsedTitle: { sr: 'Kako se SHA koristi u sertifikatima?', en: 'How is SHA used in certificates?' },
      howUsedSteps: {
        sr: [
          'CA uzima sadržaj sertifikata (ime, javni ključ, rok...)',
          'Primenjuje SHA algoritam da dobije hash (npr. 256 bita)',
          'Potpisuje taj hash svojim privatnim ključem',
          'Potpis se dodaje sertifikatu',
        ],
        en: [
          'CA takes the certificate content (name, public key, expiry...)',
          'Applies SHA algorithm to get a hash (e.g., 256 bits)',
          'Signs that hash with its private key',
          'The signature is added to the certificate',
        ],
      },
      versionsTitle: { sr: 'Verzije SHA algoritma', en: 'SHA algorithm versions' },
      sha1: {
        status: { sr: 'ZASTAREO - NE KORISTITI', en: 'DEPRECATED - DO NOT USE' },
        desc: {
          sr: 'Broken 2017. godine - moguće je napraviti kolizije. Svi moderni browseri odbijaju SHA-1 sertifikate. Koristio se do ~2016.',
          en: 'Broken in 2017 - collisions are possible. All modern browsers reject SHA-1 certificates. Used until ~2016.'
        },
      },
      sha256: {
        status: { sr: 'PREPORUČENO', en: 'RECOMMENDED' },
        desc: {
          sr: 'Deo SHA-2 familije. Standard za sve moderne sertifikate. Siguran i brz. 128-bitna sigurnost protiv kolizija.',
          en: 'Part of the SHA-2 family. Standard for all modern certificates. Secure and fast. 128-bit security against collisions.'
        },
      },
      sha384: {
        status: { sr: 'Za veću sigurnost', en: 'For higher security' },
        desc: {
          sr: 'Deo SHA-2 familije. Koristi se sa ECC P-384 ključevima. 192-bitna sigurnost. Preporučeno za vladine i visoko-sigurnosne aplikacije.',
          en: 'Part of the SHA-2 family. Used with ECC P-384 keys. 192-bit security. Recommended for government and high-security applications.'
        },
      },
      sha512: {
        status: { sr: 'Maksimalna sigurnost', en: 'Maximum security' },
        desc: {
          sr: 'Najveći SHA-2 varijanta. 256-bitna sigurnost. Može biti brži od SHA-256 na 64-bitnim procesorima. Retko potreban za sertifikate.',
          en: 'Largest SHA-2 variant. 256-bit security. Can be faster than SHA-256 on 64-bit processors. Rarely needed for certificates.'
        },
      },
      sha3: {
        status: { sr: 'Alternativa', en: 'Alternative' },
        desc: {
          sr: 'Potpuno drugačiji dizajn od SHA-2 (Keccak). Backup u slučaju da se pronađe slabost u SHA-2. Trenutno retko korišćen za sertifikate, ali siguran i standardizovan.',
          en: 'Completely different design from SHA-2 (Keccak). Backup in case a weakness is found in SHA-2. Currently rarely used for certificates, but secure and standardized.'
        },
      },
      comparisonTitle: { sr: 'Upoređenje', en: 'Comparison' },
      algorithm: { sr: 'Algoritam', en: 'Algorithm' },
      output: { sr: 'Izlaz', en: 'Output' },
      security: { sr: 'Sigurnost', en: 'Security' },
      broken: { sr: 'Broken', en: 'Broken' },
      forbidden: { sr: 'Zabranjen', en: 'Forbidden' },
      recommended: { sr: 'Preporučen', en: 'Recommended' },
      secure: { sr: 'Siguran', en: 'Secure' },
      combinationsTitle: { sr: 'Kombinacije algoritama (Signature Algorithm)', en: 'Algorithm combinations (Signature Algorithm)' },
      combinationsIntro: { sr: 'U sertifikatu ćete videti kombinaciju, npr:', en: 'In a certificate you will see a combination, e.g.:' },
    },
  },
}

export function t(key: string, lang: Language): string {
  const keys = key.split('.')
  let value: any = translations
  for (const k of keys) {
    value = value?.[k]
  }
  if (value && typeof value === 'object' && lang in value) {
    return value[lang]
  }
  return key
}
