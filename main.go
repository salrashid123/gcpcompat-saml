package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"
)

var (
	gcpBucket     = flag.String("gcpBucket", "mineral-minutia-820-cab1", "GCS Bucket to access")
	gcpObjectName = flag.String("gcpObjectName", "foo.txt", "GCS object to access")
)

func main() {
	flag.Parse()

	var storageClient *storage.Client
	ctx := context.Background()

	log.Println("Using ADC")
	var err error
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Could not create storage Client: %v", err)
	}

	bkt := storageClient.Bucket(*gcpBucket)
	obj := bkt.Object(*gcpObjectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		panic(err)
	}

}
