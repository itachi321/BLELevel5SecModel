TAMARIN = tamarin-prover 
TFLAGS = --derivcheck-timeout=0 --stop-on-trace=SEQDFS

default: proofs/type.spthy proofs/SecrecyOfDHPrivateKeyunlessRevealSK.spthy proofs/secrecy_PFS.spthy proofs/noninjective_agreement_CP_SK.spthy proofs/injective_agreement_CP_SK.spthy

interactive:
	$(TAMARIN) interactive --derivcheck-timeout=0 --interface=0.0.0.0 .


proofs/%.spthy: level5.spthy | proofs
	$(TAMARIN) --prove=$* $(TFLAGS) $< -o=$@ > $@.tmp
	@cat $@.tmp | python3 add_additional_information.py >> $@
	@rm $@.tmp


proofs: 
	mkdir -p proofs

clean:
	rm -rf proofs