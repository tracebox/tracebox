/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */
#include <string>
#include <curl/curl.h>

void curlPost(const char *pcap_filename, const char *url){
	CURL *curl;
	CURLcode res;

	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	const char buf[] = "Expect:";
	curl_global_init(CURL_GLOBAL_ALL);
	/* Fill in the file upload field */
	curl_formadd(&formpost,
	            &lastptr,
	            CURLFORM_COPYNAME, "file",
	            CURLFORM_FILE, pcap_filename,
	            CURLFORM_END);

	curl = curl_easy_init();
	if(curl) {
		headerlist = curl_slist_append(headerlist, buf);
		/* what URL that receives this POST */
	    curl_easy_setopt(curl, CURLOPT_URL, url);
	    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8);

	    /* Perform the request, res will get the return code */
	    res = curl_easy_perform(curl);
	    /* Check for errors */
	    if(res != CURLE_OK)
	      fprintf(stderr, "Could not store results on server: %s\n",
	              curl_easy_strerror(res));
	    /* cleanup */
	    curl_easy_cleanup(curl);
	    /* cleanup the formpost chain */
	    curl_formfree(formpost);
	    /* free slist */
	    curl_slist_free_all (headerlist);
	}
}
