import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { Language, t as translate } from './translations'

interface LanguageContextType {
  lang: Language
  setLang: (lang: Language) => void
  t: (key: string) => string
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined)

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem('language') as Language
    return saved || 'sr'
  })

  useEffect(() => {
    localStorage.setItem('language', lang)
  }, [lang])

  const t = (key: string) => translate(key, lang)

  return (
    <LanguageContext.Provider value={{ lang, setLang, t }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  const context = useContext(LanguageContext)
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider')
  }
  return context
}
