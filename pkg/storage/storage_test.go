package storage

/*
func TestStorageSetIDPublicKey(t *testing.T) {
	storage := New(1 * time.Hour)

	secret := uuid.New().String()
	correlationID := xid.New().String()

	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	require.Nil(t, err, "could not generate encryption keyset")

	khPub, err := khPriv.Public()
	require.Nil(t, err, "could not get keyset public-key")

	exportedPub := &keyset.MemReaderWriter{}
	err = insecurecleartextkeyset.Write(khPub, exportedPub)
	require.Nil(t, err, "could not write keyset public key")

	keyset, err := exportedPub.Read()
	require.Nil(t, err, "could not read public key of pk")

	key, err := keyset.XXX_Marshal(nil, false)
	require.Nil(t, err, "could not marshal public key")

	err = storage.SetIDPublicKey(correlationID, secret, key)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	item := storage.cache.Get(correlationID)
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.Value().(*CorrelationData)
	require.True(t, ok, "could not assert item value type as correlation data")

	require.Equal(t, secret, value.secretKey, "could not get correct secret key")
}

func TestStorageAddGetInteractions(t *testing.T) {
	storage := New(1 * time.Hour)

	secret := uuid.New().String()
	correlationID := xid.New().String()

	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	require.Nil(t, err, "could not generate encryption keyset")

	khPub, err := khPriv.Public()
	require.Nil(t, err, "could not get keyset public-key")

	exportedPub := &keyset.MemReaderWriter{}
	err = insecurecleartextkeyset.Write(khPub, exportedPub)
	require.Nil(t, err, "could not write keyset public key")

	keyset, err := exportedPub.Read()
	require.Nil(t, err, "could not read public key of pk")

	key, err := keyset.XXX_Marshal(nil, false)
	require.Nil(t, err, "could not marshal public key")

	err = storage.SetIDPublicKey(correlationID, secret, key)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	dataOriginal := []byte("hello world, this is unencrypted interaction")
	err = storage.AddInteraction(correlationID, dataOriginal)
	require.Nil(t, err, "could not add interaction to storage")

	data, err := storage.GetInteractions(correlationID, secret)
	require.Nil(t, err, "could not get interaction from storage")

	hd, err := hybrid.NewHybridDecrypt(khPriv)
	require.Nil(t, err, "could not create new decrypter")

	plaintext, err := hd.Decrypt(data[0], nil)
	require.Nil(t, err, "could not decrypt encrypted interaction data")

	require.Equal(t, dataOriginal, plaintext, "could not get correct decrypted interaction")
}
*/
