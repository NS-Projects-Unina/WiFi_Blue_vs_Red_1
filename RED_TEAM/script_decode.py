import json
import binascii

#binascii serve per convertire esadecimale in binario e viceversa

INPUT_FILE = 'dump.json'
OUTPUT_FILE = 'video.264'

def main():
    print(f"Leggo {INPUT_FILE}...")
    #LEggiamo file json con flusso grezzo
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            raw_packets = json.load(f)
    except Exception as e:
        print(f"Errore apertura JSON: {e}")
        return

    print(f"Letti {len(raw_packets)} pacchetti grezzi. Estrazione e Ordinamento...")

    # LISTA temp
    # Struttura: { 'seq': 1234, 'payload': b'...', 'type': '...' }
    rtp_buffer = []
    seen_seq = set()

    for pkt in raw_packets:
        try:
            # 1. Estrai Sequence Number
            ## Percorso: Frame -> Layers -> RTP (Real-Time Transport Protocol)
            ## devo praticamente scavare nel json per prendere i campi necessari
            rtp_layer = pkt.get('_source', {}).get('layers', {}).get('rtp', {})
            #esTraggo sequence number e payload
            seq_raw = rtp_layer.get('rtp.seq')
            payload_hex = rtp_layer.get('rtp.payload')

            if not seq_raw or not payload_hex:
                continue
            
            seq = int(seq_raw)
            
            # 2. Rimuovi duplicati
            if seq in seen_seq:
                continue
            seen_seq.add(seq)

            # 3. Pulisci Payload
            ## Rimuovi i due punti e converti da esadecimale a binario
            payload = binascii.unhexlify(payload_hex.replace(':', ''))
            
            rtp_buffer.append({
                'seq': seq,
                'payload': payload
            })

        except Exception:
            continue

    # 4. ORDINAMENTO 
    # Ordina i pacchetti in base al numero di sequenza RTP
    print("Riordino i pacchetti in base al Sequence Number...")
    rtp_buffer.sort(key=lambda x: x['seq'])

    print(f"Scrittura di {len(rtp_buffer)} pacchetti ordinati in {OUTPUT_FILE}...")

    # 5. SCRITTURA FILE H.264
    with open(OUTPUT_FILE, 'wb') as out:
        #ho dovuto mettere questa sequenza iniziale altrimenti ffmpeg non la riconosce come h264
        start_code = b'\x00\x00\x00\x01'
        
        for item in rtp_buffer:
            payload = item['payload']
            
            # Analisi header NAL
            # Il primo byte del payload contiene il NAL Unit Type (faccio AND con 0x1F per mascherare i primi 3 bit)
            nal_unit_type = (payload[0] & 0x1F)

            
            # Scarta padding (Type 0) 
            if nal_unit_type == 0:
                continue

            # SPS (per risoluzione ecc. ) / PPS(per codifica ...) / Single NAL 
            if nal_unit_type in [1, 5, 6, 7, 8]:
                out.write(start_code)
                out.write(payload)

            # Frammentati (FU-A)
            elif nal_unit_type == 28:
                fu_header = payload[1]
                start_bit = (fu_header & 0x80) >> 7
                
                if start_bit:
                    #inizio di nuovo frammento
                    #bisogna ricostruire l'header NAL originale
                    nal_ref_idc = (payload[0] & 0x60)
                    original_type = (fu_header & 0x1F)
                    new_header = nal_ref_idc | original_type

                    # Scriviamo: Start Code -> Nuovo Header -> Dati (saltando i 2 byte di header RTP)
                    out.write(start_code)
                    out.write(bytes([new_header]))
                    out.write(payload[2:])
                else:
                    out.write(payload[2:])

    print("Fatto! Prova a riprodurre ora.")
    print(f"Comando: ffplay -f h264 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
