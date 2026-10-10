import re
from typing import Dict, Any, List

class AdvancedAIService:
    def __init__(self):
        self._classifier = None
        self._ner_engine = None
        self._models_loaded = False

    def _load_models(self):
        """Carga perezosa (Lazy Loading) para evitar bloqueos al iniciar el servidor."""
        if not self._models_loaded:
            try:
                from transformers import pipeline
                # Usamos modelos optimizados para ciberseguridad multilenguaje
                self._classifier = pipeline("zero-shot-classification", model="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli")
                self._ner_engine = pipeline("ner", model="Babelscape/wikineural-multilingual-ner", aggregation_strategy="simple")
                self._models_loaded = True
            except Exception as e:
                print(f"[Advertencia IA]: No se pudieron cargar los modelos de Hugging Face ({e}). Operando en modo heurístico de alta velocidad.")
                self._models_loaded = False

    def extract_hard_entities(self, text: str) -> List[Dict[str, Any]]:
        entities = []
        # Extracción precisa de IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in ips:
            entities.append({"entity": ip, "category": "IP_ADDRESS", "start": text.find(ip), "end": text.find(ip) + len(ip)})
        
        # Extracción precisa de Puertos
        ports = re.findall(r'(?i)port[:\s]*(\d+)', text)
        for port in ports:
            entities.append({"entity": port, "category": "PORT", "start": text.find(port), "end": text.find(port) + len(port)})
            
        return entities

    def analyze(self, text: str) -> Dict[str, Any]:
        self._load_models()
        
        # Fallback heurístico si los modelos de IA no están disponibles
        if not self._models_loaded or not self._classifier:
            return self._heuristic_fallback(text)

        try:
            labels = ["Baja", "Media", "Alta", "Crítica", "No técnico"]
            class_result = self._classifier(
                text, 
                candidate_labels=labels,
                hypothesis_template="Este registro de ciberseguridad indica una amenaza de nivel {}."
            )
            
            severity = class_result['labels'][0]
            score = float(class_result['scores'][0])

            if severity == "No técnico" or score < 0.20:
                return {
                    "severity": "Informativa",
                    "confidence_score": round(score, 2),
                    "entities": [],
                    "summary": "REGISTRO NO ACCESIBLE: El texto ingresado carece de indicadores de vulnerabilidad o eventos técnicos."
                }

            hard_entities = self.extract_hard_entities(text)
            ner_results = self._ner_engine(text) if self._ner_engine else []
            ai_entities = [
                {"entity": e['word'], "category": e['entity_group'], "start": e['start'], "end": e['end']} 
                for e in ner_results
            ]
            
            all_entities = hard_entities + [e for e in ai_entities if e['entity'] not in [h['entity'] for h in hard_entities]]

            ips_encontradas = [e['entity'] for e in all_entities if e['category'] == 'IP_ADDRESS']
            ip_str = ips_encontradas[0] if ips_encontradas else "origen interno"

            summary_text = (
                f"ALERTA CYBERSENTINEL: Amenaza clasificada como {severity}. "
                f"Vector de ataque vinculado a la IP {ip_str}. Se requiere mitigación prioritaria."
            )

            return {
                "severity": severity,
                "confidence_score": round(score, 2),
                "entities": all_entities,
                "summary": summary_text
            }

        except Exception as e:
            return self._heuristic_fallback(text, error_detail=str(e))

    def _heuristic_fallback(self, text: str, error_detail: str = None) -> Dict[str, Any]:
        """Motor de respaldo ultrarrápido basado en patrones si falla el entorno de IA."""
        hard_entities = self.extract_hard_entities(text)
        has_critical_words = any(w in text.lower() for w in ["sql", "injection", "rce", "exploit", "overflow", "unauthorized"])
        
        severity = "Alta" if has_critical_words or len(hard_entities) > 0 else "Baja"
        score = 0.85 if has_critical_words else 0.40

        return {
            "severity": severity,
            "confidence_score": score,
            "entities": hard_entities,
            "summary": f"ANÁLISIS POR RESPALDO HEURÍSTICO: Actividad detectada con severidad estimada {severity}." + (f" (Nota: {error_detail})" if error_detail else "")
        }

ai_engine = AdvancedAIService()