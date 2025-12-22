#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2026 Ian Cohn
# https://www.github.com/iancohn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json
import re
from itertools import zip_longest

from autopkglib import URLGetter,Processor, ProcessorError

__all__ = ["MSStoreDownloader"]

class MSStoreDownloader(URLGetter):
    """Inspect the Microsoft App Store detail url, 
    query the store.rg-adguard.net api for download urls for the given product id. 
    download the files
    """

    description = __doc__

    input_variables = {
        "store_detail_url": {
            "required": True,
            "description": "The url of the app on the Microsoft Store site."
        },
        "download_sku": {
            "required": False,
            "description": "Which sku of the store app to download",
            "default": "full"
        },
        "download_ring": {
            "required": False,
            "description": "Which channel/ring to download",
            "default": "RP",
            "options": [
                "RP",
                "Retail",
                "Fast",
                "Slow"
            ]
        },
        "download_lang": {
            "required": False,
            "default": "en-US",
            "description": "Specify the language to download the store app."
        },
        "download_dependencies": {
            "required": False,
            "default": True,
            "description": "Whether or not to download the store app's dependencies"
        },
        "output_directory": {
            "required": False,
            "description": "The directory to download the files to. Defaults to '%RECIPE_CACHE_DIR%/downloads'"
        },
    }
    output_variables = {
        "version": {
            "description": "The version of the store app"
        },
        "total_dependencies": {
            "description": "The number of dependencies downloaded"
        },
        "total_files": {
            "description": "The number of files downloaded"
        },
        "appx_package_display_name": {
            "description": "The display name of the application"
        },
        "appx_package_name": {
            "description": "The full name of the appx package"
        },
        "appx_architecture": {
            "description": "The architecture of the AppxPackage"
        },
        "appx_vendor_identifier": {
            "description": "The unique identifier of the vendor"
        },
        "msstore_title": {
            "description": "The title (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_short_title": {
            "description": "The short title (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_description": {
            "description": "The description (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_short_description": {
            "description": "The short description (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_category_id": {
            "description": "The category id (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_publisher_id": {
            "description": "The publisher id (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_publisher_name": {
            "description": "The publisher name (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_app_website_url": {
            "description": "The app website url (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_features": {
            "description": "The app features (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_is_microsoft_product": {
            "description": "Whether or not the app is published by Microsoft (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_last_update_utc": {
            "description": "The last time the app was updated in the store (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_permissions_required": {
            "description": "The permissions required by the app (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_platforms": {
            "description": "The platforms where the app can be installed (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_privacy_url": {
            "description": "The privacy url (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_product_family_name": {
            "description": "The product family name (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_package_family_names": {
            "description": "The package family names (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_product_type": {
            "description": "The product type (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_encoded_title": {
            "description": "The encoded title (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_availability_id": {
            "description": "The availability id of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_id": {
            "description": "The sku id of the selected sku(as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_product_id": {
            "description": "The product id of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_wu_bundle_id": {
            "description": "The windows update bundle id of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_package_family_name": {
            "description": "The package family name of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_content": {
            "description": "The content of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
        "msstore_selected_sku_package_features": {
            "description": "The package features of the selected sku (as retrieved from its metadata in the Microsoft Store)"
        },
    }

    def new_version(self,version_string:str) -> tuple:
        return tuple(int(x) for x in version_string.split("."))

    def main(self):
        store_detail_url = self.env.get('store_detail_url')
        download_ring = self.env.get('download_ring')
        download_lang = self.env.get('download_lang')
        self.output(f"Getting url {store_detail_url}", 3)
        data = self.download(self.env.get('store_detail_url'), text=True)
        rxp_page_metadata = re.compile('window\.pageMetadata = (?P<page_metadata>.*)\;')
        metadata_matches = rxp_page_metadata.findall(data)
        if metadata_matches is None or len(metadata_matches) == 0:
            raise ProcessorError('Error finding metadata from Microsoft Store html')
        metadata = json.loads(metadata_matches[0])
        self.env["msstore_title"] = metadata.get('title')
        self.env["msstore_short_title"] = metadata.get('shortTitle')
        self.env["msstore_description"] = metadata.get('description')
        self.env["msstore_short_description"] = metadata.get('shortDescription')
        self.env["msstore_category_id"] = metadata.get('categoryId')
        self.env["msstore_publisher_id"] = metadata.get('publisherId')
        self.env["msstore_publisher_name"] = metadata.get('publisherName')
        self.env["msstore_app_website_url"] = metadata.get('appWebsiteUrl')
        self.env["msstore_features"] = "\n".join(metadata.get('features', []))
        self.env["msstore_is_microsoft_product"] = metadata.get('isMicrosoftProduct')
        self.env["msstore_last_update_utc"] = metadata.get('lastUpdateDateUtc')
        self.env["msstore_permissions_required"] = ", ".join(metadata.get('permissionsRequired', []))
        self.env["msstore_platforms"] = ', '.join(metadata.get('platforms',[]))
        self.env["msstore_privacy_url"] = metadata.get('privacyUrl')
        self.env["msstore_product_family_name"] = metadata.get('productFamilyName')
        self.env["msstore_package_family_names"] = ', '.join(metadata.get('packageFamilyNames', []),)
        self.env["msstore_product_type"] = metadata.get('productType')
        self.env["msstore_encoded_title"] = metadata.get('encodedTitle')
        
        skus = metadata.get('skus',[])

        selected_sku = {}
        for sku in skus:
            sku_type = sku.get('skuType','')
            if sku_type == '':
                continue
            if sku_type == self.env.get('download_sku'):
                if {} != selected_sku:
                    self.output("There appear to be multiple skus matching the selected download_sku. Only the first one will be used.", 3)
                else:
                    selected_sku = sku
            else:
                self.output(f"Skipping over sku: {sku.get('skuType')}", 3)
        self.output("Getting details of selected sku.", 3)
        if {} != selected_sku:
            self.env["msstore_selected_sku_availability_id"] = selected_sku.get('availabilityId')
            self.env["msstore_selected_sku_id"] = selected_sku.get('skuId')
            selected_fulfillment_data = json.loads(selected_sku.get('fulfillmentData', '{}'))
            self.env["msstore_selected_sku_product_id"] = selected_fulfillment_data.get('ProductId')
            self.env["msstore_selected_sku_wu_bundle_id"] = selected_fulfillment_data.get('WuBundleId')
            self.env["msstore_selected_sku_package_family_name"] = selected_fulfillment_data.get('PackageFamilyName')
            self.env["msstore_selected_sku_content"] = selected_fulfillment_data.get('Content')
            self.env["msstore_selected_sku_package_features"] = selected_fulfillment_data.get('PackageFeatures')        
        self.output("Preparing curl cmd", 3)
        curl_cmd = [self.curl_binary(), "-X","POST", 
                    "https://store.rg-adguard.net/api/GetFiles","--data-urlencode",
                    "type=url", "--data-urlencode", f"url={store_detail_url}",
                    "--data-urlencode", f"ring={download_ring}",
                    "--data-urlencode", f"lang={download_lang}"
        ]
        feed_response = self.download_with_curl(curl_cmd)
        rxp_download_file_details = re.compile('(\<a href\=\"(?P<download_url>http\:\/\/.*?)\".*?\>(?P<download_filename>.*?)\<\/a\>.*?\>(?P<download_sha1>[0-9a-z]{40}).*\>(?P<download_size>[\d\.]*\ \w\w))')
        download_file_details = rxp_download_file_details.findall(feed_response)
        self.output(f"{len(download_file_details)} individual files returned.", 3)
        url_index = rxp_download_file_details.groupindex['download_url'] - 1
        filename_index = rxp_download_file_details.groupindex['download_filename'] - 1
        #sha1_index = rxp_download_file_details.groupindex['download_sha1'] - 1
        download_folder_path = self.env.get('output_directory',os.path.join(self.env['RECIPE_CACHE_DIR'], 'downloads'))
        if os.path.exists(download_folder_path) == False:
            self.output("Creating download directory", 3)
            os.makedirs(download_folder_path)
        else:
            self.output("Download directory already exists.")
        package_base_name = selected_fulfillment_data['PackageFamilyName'].split('_')[0]
        vendor_uq_id = selected_fulfillment_data['PackageFamilyName'].split('_')[1]
        n_files_needed = 0
        n_dependencies = 0
        main_installer_files = [t[filename_index] for t in download_file_details if package_base_name in t[filename_index]]
        all_versions = [
            self.new_version(t.lstrip(f"{package_base_name}_").split('_')[0]) for t in main_installer_files
            ]
        self.env['appx_architecture'] = main_installer_files[0].split('_')[2]
        self.env['appx_package_name'] = os.path.splitext(main_installer_files[0])[0]
        self.env['appx_package_display_name'] = package_base_name
        self.env['appx_vendor_identifier'] = vendor_uq_id
        
        all_versions.sort(reverse=True)
        latest_version_tuple = all_versions[0]
        latest_version_string = ".".join([str(i) for i in list(latest_version_tuple)])
        self.output(f"Latest version: {latest_version_string}", 3)
        self.env['version'] = latest_version_string

        for detail in download_file_details:
            file_match_string = f"{package_base_name}_{latest_version_string}_"
            if package_base_name in detail[filename_index]:
                if file_match_string not in detail[filename_index]:
                    self.output(f"{detail[filename_index]} appears to be for an older version. Skipping it.", 4)
                    continue
            elif self.env.get('download_dependencies') == False:
                self.output(f"{detail[filename_index]} is a dependency and download_dependencies was evaluated 'False'. Skipping it.")
                continue
            else:
                n_dependencies += 1
            n_files_needed += 1
            filename = os.path.join(download_folder_path, detail[filename_index])
            self.download_to_file(detail[url_index], filename)
        
        self.output(f"{n_files_needed}/{len(download_file_details)} files determined to be needed for this application.", 3)
        self.env['total_files'] = n_files_needed
        self.env['total_dependencies'] = n_dependencies

if __name__ == "__main__":
    PROCESSOR = MSStoreDownloader()
    PROCESSOR.execute_shell()
