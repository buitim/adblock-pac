// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Mon, 20 Jan 2020 08:58:31 GMT
// Created with command: easylist_pac.py -d ./Assets
//
// http://www.gnu.org/licenses/lgpl.txt
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy server.
//
// Influenced in part by code from King of the PAC from http://securemecca.com/pac.html

// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
// var blackhole_ip_port = "127.0.0.1:8119";  // ngnix-hosted blackhole
// var blackhole_ip_port = "8.8.8.8:53";      // GOOG DNS blackhole; do not use: no longer works with iOS 11—causes long waits on some sites
var blackhole_ip_port = "127.0.0.1:8119";    // on iOS a working blackhole requires return code 200;
// e.g. use the adblock2privoxy nginx server as a blackhole
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

// EasyList rules:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet
// https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
// https://adblockplus.org/blog/investigating-filter-matching-algorithms
// 
// Strategies to convert EasyList rules to Javascript tests:
// 
// In general:
// 1. Preference for performance over 1:1 EasyList functionality
// 2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
// 3. Exact matches: use Object hashing (very fast); use efficient NFA RegExp's for all else
// 4. Divide and conquer specific cases to avoid large RegExp's
// 5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
// 6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin
// 
// scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings
// 
// EasyList rules:
// 
// || domain anchor
// 
// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// 
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// 
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// 
// url parts e.g. a.b^c&d|
// 
// All cases RegExp.test(url)
// Except: |http://a.b. Treat these as domain anchors after stripping the scheme
// 
// regex e.g. /r/
// 
// All cases RegExp.test(url)
// 
// @@ exceptions
// 
// Flag as "good" versus "bad" default
// 
// Variable name conventions (example that defines the rule):
// 
// bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
// bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
// 
// 71 rules:
var good_da_host_JSON = { "apple.com": null,
"icloud.com": null,
"apple-dns.net": null,
"swcdn.apple.com": null,
"init.itunes.apple.com": null,
"init-cdn.itunes-apple.com.akadns.net": null,
"itunes.apple.com.edgekey.net": null,
"setup.icloud.com": null,
"p32-escrowproxy.icloud.com": null,
"p32-escrowproxy.fe.apple-dns.net": null,
"keyvalueservice.icloud.com": null,
"keyvalueservice.fe.apple-dns.net": null,
"p32-bookmarks.icloud.com": null,
"p32-bookmarks.fe.apple-dns.net": null,
"p32-ckdatabase.icloud.com": null,
"p32-ckdatabase.fe.apple-dns.net": null,
"configuration.apple.com": null,
"configuration.apple.com.edgekey.net": null,
"mesu.apple.com": null,
"mesu-cdn.apple.com.akadns.net": null,
"mesu.g.aaplimg.com": null,
"gspe1-ssl.ls.apple.com": null,
"gspe1-ssl.ls.apple.com.edgekey.net": null,
"api-glb-bos.smoot.apple.com": null,
"query.ess.apple.com": null,
"query-geo.ess-apple.com.akadns.net": null,
"query.ess-apple.com.akadns.net": null,
"setup.fe.apple-dns.net": null,
"gsa.apple.com": null,
"gsa.apple.com.akadns.net": null,
"icloud-content.com": null,
"usbos-edge.icloud-content.com": null,
"usbos.ce.apple-dns.net": null,
"lcdn-locator.apple.com": null,
"lcdn-locator.apple.com.akadns.net": null,
"lcdn-locator-usuqo.apple.com.akadns.net": null,
"cl1.apple.com": null,
"cl2.apple.com": null,
"cl3.apple.com": null,
"cl4.apple.com": null,
"cl5.apple.com": null,
"cl1-cdn.origin-apple.com.akadns.net": null,
"cl2-cdn.origin-apple.com.akadns.net": null,
"cl3-cdn.origin-apple.com.akadns.net": null,
"cl4-cdn.origin-apple.com.akadns.net": null,
"cl5-cdn.origin-apple.com.akadns.net": null,
"cl1.apple.com.edgekey.net": null,
"cl2.apple.com.edgekey.net": null,
"cl3.apple.com.edgekey.net": null,
"cl4.apple.com.edgekey.net": null,
"cl5.apple.com.edgekey.net": null,
"xp.apple.com": null,
"xp.itunes-apple.com.akadns.net": null,
"mt-ingestion-service-pv.itunes.apple.com": null,
"p32-sharedstreams.icloud.com": null,
"p32-sharedstreams.fe.apple-dns.net": null,
"p32-fmip.icloud.com": null,
"p32-fmip.fe.apple-dns.net": null,
"gsp-ssl.ls.apple.com": null,
"gsp-ssl.ls-apple.com.akadns.net": null,
"gsp-ssl.ls2-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com": null,
"gspe35-ssl.ls-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com.edgekey.net": null,
"gsp64-ssl.ls.apple.com": null,
"gsp64-ssl.ls-apple.com.akadns.net": null,
"mt-ingestion-service-st11.itunes.apple.com": null,
"mt-ingestion-service-st11.itunes-apple.com.akadns.net": null,
"microsoft.com": null,
"mozilla.com": null,
"mozilla.org": null };
var good_da_host_exact_flag = 71 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_hostpath_JSON = {  };
var good_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^$/;
var good_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_RegExp = /^$/;
var good_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 39 rules:
var good_da_host_exceptions_JSON = { "iad.apple.com": null,
"iadsdk.apple.com": null,
"iadsdk.apple.com.edgekey.net": null,
"bingads.microsoft.com": null,
"azure.bingads.trafficmanager.net": null,
"choice.microsoft.com": null,
"choice.microsoft.com.nsatc.net": null,
"corpext.msitadfs.glbdns2.microsoft.com": null,
"corp.sts.microsoft.com": null,
"df.telemetry.microsoft.com": null,
"diagnostics.support.microsoft.com": null,
"feedback.search.microsoft.com": null,
"i1.services.social.microsoft.com": null,
"i1.services.social.microsoft.com.nsatc.net": null,
"redir.metaservices.microsoft.com": null,
"reports.wes.df.telemetry.microsoft.com": null,
"services.wes.df.telemetry.microsoft.com": null,
"settings-sandbox.data.microsoft.com": null,
"settings-win.data.microsoft.com": null,
"sqm.df.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com.nsatc.net": null,
"statsfe1.ws.microsoft.com": null,
"statsfe2.update.microsoft.com.akadns.net": null,
"statsfe2.ws.microsoft.com": null,
"survey.watson.microsoft.com": null,
"telecommand.telemetry.microsoft.com": null,
"telecommand.telemetry.microsoft.com.nsatc.net": null,
"telemetry.urs.microsoft.com": null,
"vortex.data.microsoft.com": null,
"vortex-sandbox.data.microsoft.com": null,
"vortex-win.data.microsoft.com": null,
"cy2.vortex.data.microsoft.com.akadns.net": null,
"watson.microsoft.com": null,
"watson.ppe.telemetry.microsoft.comwatson.telemetry.microsoft.com": null,
"watson.telemetry.microsoft.com.nsatc.net": null,
"wes.df.telemetry.microsoft.com": null,
"win10.ipv6.microsoft.com": null,
"www.bingads.microsoft.com": null };
var good_da_host_exceptions_exact_flag = 39 > 0 ? true : false;  // test for non-zero number of rules

// 1492 rules:
var bad_da_host_JSON = { "adservice.google.com": null,
"ad.turn.com": null,
"ad.smartclip.net": null,
"ad.yadro.ru": null,
"ads.yldmgrimg.net": null,
"counter.yadro.ru": null,
"ads.yimg.com": null,
"ad.tbn.ru": null,
"banners.freett.com": null,
"pixel.mtrcs.samba.tv": null,
"ads.nordichardware.com": null,
"aktrack.pubmatic.com": null,
"ad.rambler.ru": null,
"ads.tripod.com": null,
"counter.rambler.ru": null,
"richmedia.yimg.com": null,
"ads.msn.com": null,
"ads.thestar.com": null,
"ads.linkedin.com": null,
"ads.adfox.ru": null,
"ads.contentabc.com": null,
"ad.media-servers.net": null,
"widget.privy.com": null,
"pixel.adsafeprotected.com": null,
"ads.advance.net": null,
"ads2.contentabc.com": null,
"pixel.watch": null,
"ads.gamecity.net": null,
"cdn.segment.com": null,
"ads3.contentabc.com": null,
"ads.kabooaffiliates.com": null,
"ads.larryaffiliates.com": null,
"ads.affiliates-spinit.com": null,
"ads4.gamecity.net": null,
"ads.sexinyourcity.com": null,
"adnet.biz": null,
"ads2.gamecity.net": null,
"ads.creative-serving.com": null,
"adnet.ru": null,
"ad.technoratimedia.com": null,
"clicks.equantum.com": null,
"ads.shopstyle.com": null,
"content.ad": null,
"freestats.tv": null,
"ads.olivebrandresponse.com": null,
"ad.100.tbn.ru": null,
"adland.ru": null,
"warlog.ru": null,
"ad.nozonedata.com": null,
"ads.crakmedia.com": null,
"ads3.gamecity.net": null,
"banner.ad.nu": null,
"inetlog.ru": null,
"trafficfactory.biz": null,
"adserver1.backbeatmedia.com": null,
"spinbox.techtracker.com": null,
"ad.bitmedia.io": null,
"adserver.sharewareonline.com": null,
"ads.bittorrent.com": null,
"ktu.sv2.biz": null,
"regularimptracker.xyz": null,
"adsrv.eacdn.com": null,
"ads.ad-center.com": null,
"eu1.madsone.com": null,
"tagan.adlightning.com": null,
"ads.bing.com": null,
"bans.bride.ru": null,
"analytics.myfinance.com": null,
"teads.tv": null,
"adpenguin.biz": null,
"ads.adverline.com": null,
"adbrite.com": null,
"affiliates.allposters.com": null,
"adriver.ru": null,
"stat.webmedia.pl": null,
"musiccounter.ru": null,
"li.gatehousemedia.com": null,
"banner.rbc.ru": null,
"textads.biz": null,
"adserver.bing.com": null,
"ads.saymedia.com": null,
"m1.webstats4u.com": null,
"log.logrocket.io": null,
"munchkin.marketo.net": null,
"fastclick.com": null,
"adapt.tv": null,
"newt1.adultadworld.com": null,
"hotlog.ru": null,
"ads.mediasmart.es": null,
"click.a-ads.com": null,
"ads.videosz.com": null,
"ads7.gamecity.net": null,
"static.a-ads.com": null,
"ads.viksaffiliates.com": null,
"ads.casumoaffiliates.com": null,
"ads.quasaraffiliates.com": null,
"ads.toplayaffiliates.com": null,
"ads.thrillsaffiliates.com": null,
"adap.tv": null,
"gmads.net": null,
"bullseye.backbeatmedia.com": null,
"ad.pandora.tv": null,
"ads.4tube.com": null,
"banners.adultfriendfinder.com": null,
"cloudcoins.biz": null,
"chameleon.ad": null,
"affiliates.thrixxx.com": null,
"ad.a-ads.com": null,
"analytics.google.com": null,
"ad.amgdgt.com": null,
"bannerlandia.com.ar": null,
"ad.seznam.cz": null,
"ads.img.co.za": null,
"cdn.bannerflow.com": null,
"static.itrack.it": null,
"adzerk.s3.amazonaws.com": null,
"m32.media": null,
"convrse.media": null,
"partnerad.l.google.com": null,
"www-google-analytics.l.google.com": null,
"adsatt.espn.starwave.com": null,
"track.adform.net": null,
"ads.adshareware.net": null,
"clientmetrics-pa.googleapis.com": null,
"track.anchorfree.com": null,
"as1.advfn.com": null,
"pagead.l.google.com": null,
"ads.adultfriendfinder.com": null,
"geobanner.adultfriendfinder.com": null,
"ads.youtube.com": null,
"fastclick.net": null,
"forex-affiliate.net": null,
"ads.tmcs.net": null,
"ads6.gamecity.net": null,
"acceptable.a-ads.com": null,
"ad3.pamedia.com.au": null,
"video-stats.video.google.com": null,
"cookies.cmpnet.com": null,
"adserver.virginmedia.com": null,
"ad.sensismediasmart.com.au": null,
"ads.twitter.com": null,
"kliks.nl": null,
"ads.yahoo.com": null,
"publicidad.elmundo.es": null,
"adv.freeonline.it": null,
"ads.wikia.nocookie.net": null,
"questaffiliates.net": null,
"affiliates.ultrahosting.com": null,
"4affiliate.net": null,
"audit.median.hu": null,
"tracker.bannerflow.com": null,
"adspeed.net": null,
"shinystat.it": null,
"ads.imgur.com": null,
"top100.mafia.ru": null,
"trafficz.net": null,
"belstat.nl": null,
"adserver.adultfriendfinder.com": null,
"ads.as4x.tmcs.ticketmaster.com": null,
"checkstat.nl": null,
"ads.ninemsn.com.au": null,
"ads.co.com": null,
"adsfac.net": null,
"readserver.net": null,
"ads.yap.yahoo.com": null,
"adspirit.de": null,
"adpepper.nl": null,
"spinbox.versiontracker.com": null,
"optimost.com": null,
"shellcat.ru": null,
"ads.nzcity.co.nz": null,
"banners.videosz.com": null,
"affiliates.thinkhost.net": null,
"gotraffic.net": null,
"ads.digitalmedianet.com": null,
"ads.whoishostingthis.com": null,
"adserver.hardsextube.com": null,
"trafficspaces.net": null,
"traffictrader.net": null,
"ads24h.net": null,
"adk2.co": null,
"ad4mat.de": null,
"ads.vgchartz.com": null,
"adworx.nl": null,
"ads.vnumedia.com": null,
"cityads.telus.net": null,
"stat.pl": null,
"ads.gplusmedia.com": null,
"affiliate.mogs.com": null,
"affiliate.viator.com": null,
"ads.factorymedia.com": null,
"ads.mediaodyssey.com": null,
"affiliate.mercola.com": null,
"affiliate.treated.com": null,
"affiliate.offgamers.com": null,
"affiliate.1800flowers.com": null,
"ads.horyzon-media.com": null,
"ads.kelbymediagroup.com": null,
"quantcast.com": null,
"ads.activestate.com": null,
"rb1.design.ru": null,
"affiliates.globat.com": null,
"adcell.de": null,
"targad.de": null,
"adpepper.dk": null,
"ads.weather.ca": null,
"ads.yourfreedvds.com": null,
"mail-ads.google.com": null,
"zanox-affiliate.de": null,
"sponsorpro.de": null,
"rankingchart.de": null,
"ad.jamba.net": null,
"ranking-charts.de": null,
"onclickads.net": null,
"ads.fasttrack-ignite.com": null,
"staticwebcontent.net": null,
"adrotator.se": null,
"s.adroll.com": null,
"ads.optusnet.com.au": null,
"partnercash.de": null,
"ads1.msn.com": null,
"jinkads.de": null,
"adsmart.net": null,
"mycounter.ua": null,
"analytics.yahoo.com": null,
"adtegrity.net": null,
"banner.img.co.za": null,
"adrotate.de": null,
"ads.adstream.com.ro": null,
"adverticum.net": null,
"admerize.be": null,
"i1media.no": null,
"carbonads.net": null,
"clikerz.net": null,
"ad-serverparc.nl": null,
"clicklink.jp": null,
"auctionads.net": null,
"i-clicks.net": null,
"urldata.net": null,
"ads.tripod.lycos.nl": null,
"r.logrocket.io": null,
"adserver.hardwareanalysis.com": null,
"clickwith.bid": null,
"adsfac.eu": null,
"techclicks.net": null,
"nedstatbasic.net": null,
"ads.stackoverflow.com": null,
"bannerconnect.net": null,
"start.freeze.com": null,
"adserver.yahoo.com": null,
"ads.websiteservices.com": null,
"go-clicks.de": null,
"adinterax.com": null,
"ad.liveinternet.ru": null,
"affiliate.doubleyourdating.com": null,
"clicktag.de": null,
"ads.mail.bg": null,
"euros4click.de": null,
"webstat.net": null,
"gamesites100.net": null,
"phpmyvisites.net": null,
"topgamesites.net": null,
"adtrade.net": null,
"affiliate.gamestop.com": null,
"adstage.io": null,
"googlesyndication.com": null,
"tns-counter.ru": null,
"adbard.net": null,
"adhoc4.net": null,
"havamedia.net": null,
"bannermarkt.nl": null,
"adcept.net": null,
"adlure.net": null,
"nuggad.net": null,
"ad-space.net": null,
"aistat.net": null,
"ad-balancer.net": null,
"adaction.de": null,
"adprofile.net": null,
"admanagement.ch": null,
"track.addevent.com": null,
"adinjector.net": null,
"ad4mat.net": null,
"affiliatefuel.com": null,
"affiliatewindow.com": null,
"myaffiliateprogram.com": null,
"herbalaffiliateprogram.com": null,
"ad-delivery.net": null,
"eu-adcenter.net": null,
"ad-pay.de": null,
"yab-adimages.s3.amazonaws.com": null,
"adtrace.org": null,
"cash4popup.de": null,
"partnerads.ysm.yahoo.com": null,
"adtiger.de": null,
"advertisingtag.net": null,
"adstacks.in": null,
"mediascale.de": null,
"adtrak.net": null,
"adbroker.de": null,
"adrolays.de": null,
"adsolut.in": null,
"ads.as4x.tmcs.net": null,
"adcontrolsolutions.net": null,
"adverticus.de": null,
"coupling-media.de": null,
"tcads.net": null,
"ads.tso.dennisnet.co.uk": null,
"ads.administrator.de": null,
"witch-counter.de": null,
"adback.co": null,
"layer-ad.de": null,
"trackedweb.net": null,
"adpia.vn": null,
"commindo-media-ressourcen.de": null,
"trackedlink.net": null,
"aztracking.net": null,
"pctracking.net": null,
"cointraffic.io": null,
"movad.net": null,
"adimages.carsoup.com": null,
"entrecard.s3.amazonaws.com": null,
"supertracking.net": null,
"fusionads.net": null,
"hilltopads.net": null,
"adsfac.us": null,
"etracker.de": null,
"mobperads.net": null,
"leadboltads.net": null,
"hyperbanner.net": null,
"mystat.pl": null,
"surfmusik-adserver.de": null,
"openads.org": null,
"wondoads.de": null,
"ads.geekswithblogs.net": null,
"d.adroll.com": null,
"ad-balancer.at": null,
"boersego-ads.de": null,
"admixer.net": null,
"digital-ads.s3.amazonaws.com": null,
"alexa-sitestats.s3.amazonaws.com": null,
"ads.egrana.com.br": null,
"webmaster-partnerprogramme24.de": null,
"affiliatetracking.net": null,
"top100-images.rambler.ru": null,
"adserver01.de": null,
"d2cmedia.ca": null,
"aidu-ads.de": null,
"layer-ads.de": null,
"wholesaletraffic.info": null,
"chart.dk": null,
"adserver.pl": null,
"ads.oneplace.com": null,
"adsklick.de": null,
"adsponse.de": null,
"adserver.aol.fr": null,
"bannercommunity.de": null,
"auto-bannertausch.de": null,
"ads.oddschecker.com": null,
"banner-exchange-24.de": null,
"adscale.de": null,
"topsite.lv": null,
"ads.motormedia.nl": null,
"ads.ibest.com.br": null,
"adscience.nl": null,
"media01.eu": null,
"adsend.de": null,
"ads.financialcontent.com": null,
"mediaarea.eu": null,
"microstatic.pl": null,
"ads.forbes.net": null,
"statistik-gallup.net": null,
"affiliate.travelnow.com": null,
"mpstat.us": null,
"hightrafficads.com": null,
"mytrafficads.com": null,
"wetrack.it": null,
"ads.sun.com": null,
"ads.virtual-nights.com": null,
"sageanalyst.net": null,
"adserving.unibet.com": null,
"offer.sponsorpay.com": null,
"ads.cc-dt.com": null,
"ads.ask.com": null,
"adservinginternational.com": null,
"ads.5ci.lt": null,
"img.prohardver.hu": null,
"adserversolutions.com": null,
"ad.simgames.net": null,
"adservingfront.com": null,
"adhese.be": null,
"admeridianads.com": null,
"adserverplus.com": null,
"big-bang-ads.com": null,
"text-link-ads.com": null,
"adserverpub.com": null,
"infinite-ads.com": null,
"adcannyads.com": null,
"adsymptotic.com": null,
"webcounter.cz": null,
"admidadsp.com": null,
"adsoftware.com": null,
"ads4homes.com": null,
"adscholar.com": null,
"adsiduous.com": null,
"adsmarket.com": null,
"adsoldier.com": null,
"adsynergy.com": null,
"adsrvus.com": null,
"webads.nl": null,
"adsupply.com": null,
"adside.com": null,
"adsrvx.com": null,
"abc-ads.com": null,
"adskpak.com": null,
"ads180.com": null,
"adsdaq.com": null,
"adspsp.com": null,
"adsxyz.com": null,
"ads.ncm.com": null,
"ads.ole.com": null,
"ads.pof.com": null,
"ads8.com": null,
"ads.goyk.com": null,
"ads.alt.com": null,
"ads.amdmb.com": null,
"ads.jpost.com": null,
"ads.ndtv1.com": null,
"ads.scifi.com": null,
"record.affiliates.karjalakasino.com": null,
"ads.domain.com": null,
"ads.domeus.com": null,
"ads.filmup.com": null,
"ads.guru3d.com": null,
"ads.kinxxx.com": null,
"ads.mmania.com": null,
"ads.okcimg.com": null,
"ads.pennet.com": null,
"ads.techtv.com": null,
"ads.bigfoot.com": null,
"ads.epltalk.com": null,
"ads.ferianc.com": null,
"ads.flooble.com": null,
"ads.kompass.com": null,
"ads.shizmoo.com": null,
"ads.uncrate.com": null,
"ads.elcarado.com": null,
"ads.getlucky.com": null,
"ads.psd2html.com": null,
"ads.gaming1.com": null,
"ads.brabys.com": null,
"ads.gamespyid.com": null,
"ads.horsehero.com": null,
"ads.lordlucky.com": null,
"ads.mobilebet.com": null,
"ads.xtribeapp.com": null,
"ads.printscr.com": null,
"ads.easy-forex.com": null,
"ads.gamershell.com": null,
"ads.gradfinder.com": null,
"ads.justhungry.com": null,
"ads.newgrounds.com": null,
"ads.datingyes.com": null,
"ads.aspalliance.com": null,
"ads.electrocelt.com": null,
"ads.elitetrader.com": null,
"ads.gsmexchange.com": null,
"sponsorads.de": null,
"cmp.dmgmediaprivacy.co.uk": null,
"ads.contactmusic.com": null,
"ads.eagletribune.com": null,
"ads.gsm-exchange.com": null,
"ads.satyamonline.com": null,
"kmpiframe.keepmeposted.com.mt": null,
"ads.dailycamera.com": null,
"ads.directionsmag.com": null,
"ads.grindinggears.com": null,
"ads.socialtheater.com": null,
"ads.abovetopsecret.com": null,
"ads.digital-digest.com": null,
"ads.mobilautomaten.com": null,
"ads.wineenthusiast.com": null,
"ads.suomiautomaatti.com": null,
"ads.travelaudience.com": null,
"emediate.eu": null,
"ads.lesbianpersonals.com": null,
"ads.totallyfreestuff.com": null,
"comprabanner.it": null,
"bannerads.de": null,
"displayadsmedia.com": null,
"ads1.mediacapital.pt": null,
"neocounter.neoworx-blog-tools.net": null,
"mtrcs.samba.tv": null,
"ads.livenation.com": null,
"ads.bonniercorp.com": null,
"bannershotlink.perfectgonzo.com": null,
"crta.dailymail.co.uk": null,
"ads2.rne.com": null,
"ads.passion.com": null,
"adition.de": null,
"mediabridge.cc": null,
"staticads.btopenworld.com": null,
"dontstopmyads.live": null,
"sharepointads.com": null,
"shareadspace.com": null,
"adblade.org": null,
"ads.canalblog.com": null,
"theclickads.com": null,
"blogtoplist.se": null,
"impressionmedia.cz": null,
"pub.realmedia.fr": null,
"ads.jobsite.co.uk": null,
"ad.eurosport.com": null,
"ads.powweb.com": null,
"clicktrace.info": null,
"clickedyclick.com": null,
"ads.cc": null,
"ads.independent.com.mt": null,
"ad.xiaomi.com": null,
"ads.seniorfriendfinder.com": null,
"ads.gamigo.de": null,
"tsyndicate.com": null,
"ads.deviantart.com": null,
"adzerk.net": null,
"rmads.msn.com": null,
"adalliance.io": null,
"at-adserver.alltop.com": null,
"ads.ultimate-guitar.com": null,
"ads.phpclasses.org": null,
"adserver.bizhat.com": null,
"adserver.viagogo.com": null,
"adserver.aidameter.com": null,
"adserver.sciflicks.com": null,
"adserver.spankaway.com": null,
"adserver.nydailynews.com": null,
"admanmedia.com": null,
"campaign.bharatmatrimony.com": null,
"adserver.irishwebmasterforum.com": null,
"affili.net": null,
"ads.harpers.org": null,
"ads.expat-blog.biz": null,
"adbooth.net": null,
"ads.heartlight.org": null,
"ads.webmasterpoint.org": null,
"utils.mediageneral.net": null,
"ads.linuxfoundation.org": null,
"adstat.4u.pl": null,
"ng3.ads.warnerbros.com": null,
"adsrvr.org": null,
"advisormedia.cz": null,
"addfreestats.com": null,
"ads.jewishfriendfinder.com": null,
"doubleclick.de": null,
"athena-ads.wikia.com": null,
"wikia-ads.wikia.com": null,
"adserver.portugalmail.pt": null,
"ads.bigchurch.com": null,
"ads1.rne.com": null,
"adfries.info": null,
"adyoulike.com": null,
"advertmedia.de": null,
"ads.affiliates.match.com": null,
"adimages.been.com": null,
"stats.wp.com": null,
"ads4.virtual-nights.com": null,
"fpctraffic.com": null,
"protraffic.com": null,
"ads.y-0.net": null,
"ads.infi.net": null,
"ads.aceweb.net": null,
"ads.kaktuz.net": null,
"craktraffic.com": null,
"fpctraffic2.com": null,
"traffichunt.com": null,
"lightcast.leadscoringcenter.com": null,
"barnesandnoble.bfast.com": null,
"adlooxtracking.com": null,
"ru-traffic.com": null,
"play4traffic.com": null,
"trafficswarm.com": null,
"yieldtraffic.com": null,
"adetracking.com": null,
"ads.networksolutions.com": null,
"blast4traffic.com": null,
"casinotraffic.com": null,
"trafficholder.com": null,
"trafficleader.com": null,
"trafficsecrets.com": null,
"adsrv.deviantart.com": null,
"blogherads.com": null,
"audit.quantcast.mgr.consensu.org": null,
"sixsigmatraffic.com": null,
"ads.economist.com": null,
"ads.mgnetwork.com": null,
"clicks.mods.de": null,
"traffic-exchange.com": null,
"advertisingbanners.com": null,
"trafficstrategies.com": null,
"ads.recoletos.es": null,
"adserver.oddschecker.com": null,
"keymedia.hu": null,
"clickthrutraffic.com": null,
"adn.lrb.co.uk": null,
"ads.amigos.com": null,
"liquidad.narrowcastmedia.com": null,
"ads.gawker.com": null,
"traktrafficflow.com": null,
"ad-score.com": null,
"ad.abcnews.com": null,
"ads.dennisnet.co.uk": null,
"adserver1.ogilvy-interactive.de": null,
"affiliates.rozetka.com.ua": null,
"hsadspixel.net": null,
"valueclickmedia.com": null,
"ads.dazoot.ro": null,
"ads2.oneplace.com": null,
"ads.tripod.lycos.de": null,
"content.acc-hd.de": null,
"adserve.ams.rhythmxchange.com": null,
"ads.ztod.com": null,
"ad.tv2.no": null,
"spykemediatrack.com": null,
"adblockanalytics.com": null,
"ads.emirates.net.ae": null,
"ads.isoftmarketing.com": null,
"ad.yourmedia.com": null,
"adserver.cams.com": null,
"adnet.worldreviewer.com": null,
"adx.allstar.cz": null,
"mystat-in.net": null,
"netclickstats.com": null,
"cnt.spbland.ru": null,
"adworx.at": null,
"adnet.de": null,
"allosponsor.com": null,
"websponsors.com": null,
"adserver1-images.backbeatmedia.com": null,
"affiliate.dtiserv.com": null,
"adition.net": null,
"valuesponsor.com": null,
"domainsponsor.com": null,
"ad.period-calendar.com": null,
"admotion.com.ar": null,
"affiliates.digitalriver.com": null,
"adcontent.gamespy.com": null,
"ads.bloomberg.com": null,
"google-analytics.com": null,
"googleanalytics.com": null,
"ad.choiceradio.com": null,
"ad.digitallook.com": null,
"ad.jetsoftware.com": null,
"ad.preferances.com": null,
"ads.mic.com": null,
"ads2.virtual-nights.com": null,
"mybloglog.com": null,
"arc1.msn.com": null,
"ad.caradisiac.com": null,
"ad.twitchguru.com": null,
"ad.cooks.com": null,
"ads.fotosidan.se": null,
"images-pw.secureserver.net": null,
"ad.keenspace.com": null,
"simpleanalytics.io": null,
"click.kmindex.ru": null,
"webtracker.jp": null,
"adsystem.simplemachines.org": null,
"adnet.asahi.com": null,
"ad.auditude.com": null,
"chartbeat.net": null,
"popads.net": null,
"ads.footymad.net": null,
"ads5.virtual-nights.com": null,
"ad.anuntis.com": null,
"adimages.homestore.com": null,
"openad.travelnow.com": null,
"ads.aol.co.uk": null,
"adsatt.abc.starwave.com": null,
"clicktracks.com": null,
"adnetwork.net": null,
"brand-display.com": null,
"brandreachsys.com": null,
"ad.abctv.com": null,
"trafficz.com": null,
"adserver.theonering.net": null,
"metrics.foxnews.com": null,
"log.btopenworld.com": null,
"adtology.com": null,
"ads-game-187f4.firebaseapp.com": null,
"ad.infoseek.com": null,
"ad1.emule-project.org": null,
"ads.smartclick.com": null,
"ads.canoe.ca": null,
"ads.mcafee.com": null,
"stat.cliche.se": null,
"ads.nyx.cz": null,
"stat24.com": null,
"adview.ppro.de": null,
"ads.rcs.it": null,
"banner.mindshare.de": null,
"discountclick.com": null,
"ads.cybersales.cz": null,
"adv.nexthardware.com": null,
"ad.domainfactory.de": null,
"ads.freecity.de": null,
"ads.mariuana.it": null,
"trekdata.com": null,
"ad.nachtagenten.de": null,
"ad1.pamedia.com.au": null,
"clickz.com": null,
"clickadz.com": null,
"exoclick.com": null,
"adclient1.tucows.com": null,
"softclick.com.br": null,
"alclick.com": null,
"piquantpigs.com": null,
"optimize-stats.voxmedia.com": null,
"bigclicks.com": null,
"bizzclick.com": null,
"clickfuse.com": null,
"leadclick.com": null,
"vericlick.com": null,
"counts.tucows.com": null,
"quantserve.com": null,
"adserver2.mindshare.de": null,
"adz2you.com": null,
"clickbooth.com": null,
"clickhouse.com": null,
"indieclick.com": null,
"maxonclick.com": null,
"validclick.com": null,
"zeusclicks.com": null,
"mediaz.angloinfo.com": null,
"beacon.gu-web.net": null,
"adfarm.mediaplex.com": null,
"clickhype.com": null,
"treasuredata.com": null,
"buzzonclick.com": null,
"clickagents.com": null,
"nitroclicks.com": null,
"ad.lupa.cz": null,
"ad.grafika.cz": null,
"ads1.virtual-nights.com": null,
"clickbrokers.com": null,
"clickdensity.com": null,
"clickxchange.com": null,
"cliksolution.com": null,
"directaclick.com": null,
"incentaclick.com": null,
"tracking.internetstores.de": null,
"ads.betfair.com": null,
"ads.space.com": null,
"sitedataprocessing.com": null,
"clickboothlnk.com": null,
"scorecardresearch.com": null,
"ads.medienhaus.de": null,
"inspectorclick.com": null,
"propellerclick.com": null,
"ad.allstar.cz": null,
"click2freemoney.com": null,
"clickthruserver.com": null,
"ads.newmedia.cz": null,
"absoluteclickscom.com": null,
"exchangeclicksonline.com": null,
"adsensecustomsearchads.com": null,
"clickonometrics.pl": null,
"clksite.com": null,
"clickhereforcellphones.com": null,
"ads.planet.nl": null,
"chartboost.com": null,
"ad.prv.pl": null,
"admagnet.net": null,
"ads.trinitymirror.co.uk": null,
"assets1.exgfnetwork.com": null,
"adv-adserver.com": null,
"ads1-adnow.com": null,
"ads3-adnow.com": null,
"ad.cgi.cz": null,
"optmd.com": null,
"adman.gr": null,
"enquisite.com": null,
"geovisite.com": null,
"sitemeter.com": null,
"jcount.com": null,
"hs-analytics.net": null,
"watchingthat.com": null,
"addme.com": null,
"adjix.com": null,
"adjug.com": null,
"admex.com": null,
"adrta.com": null,
"adtng.com": null,
"advnt.com": null,
"tapad.com": null,
"partners.priceline.com": null,
"zmedia.com": null,
"rankyou.com": null,
"ads.internic.co.il": null,
"marketingsolutions.yahoo.com": null,
"muwmedia.com": null,
"tlvmedia.com": null,
"banner.northsky.com": null,
"ad.way.cz": null,
"popuptraffic.com": null,
"prsitecheck.com": null,
"99count.com": null,
"counted.com": null,
"aim4media.com": null,
"lfstmedia.com": null,
"mediamath.com": null,
"mediatext.com": null,
"mediavine.com": null,
"ad.reunion.com": null,
"neighborlywatch.com": null,
"adcash.com": null,
"adgoto.com": null,
"adisfy.com": null,
"adizio.com": null,
"adloox.com": null,
"admeta.com": null,
"adthis.com": null,
"adtilt.com": null,
"adtoll.com": null,
"adtoma.com": null,
"gamesites200.com": null,
"cdn.onesignal.com": null,
"metaffiliation.com": null,
"netaffiliation.com": null,
"adserver.portugalmail.net": null,
"top-site-list.com": null,
"adbuyer3.lycos.com": null,
"log.pinterest.com": null,
"caniamedia.com": null,
"casalmedia.com": null,
"hydramedia.com": null,
"lucidmedia.com": null,
"vertamedia.com": null,
"optmstr.com": null,
"518ad.com": null,
"adyea.com": null,
"ad-tech.com": null,
"ad4game.com": null,
"adbuyer.com": null,
"adhaven.com": null,
"adledge.com": null,
"admantx.com": null,
"admized.com": null,
"adnotch.com": null,
"adotmob.com": null,
"adplxmd.com": null,
"adrazzi.com": null,
"adwhirl.com": null,
"adxpose.com": null,
"adzones.com": null,
"cpalead.com": null,
"twittad.com": null,
"valuead.com": null,
"popupmoney.com": null,
"24pm-affiliation.com": null,
"cdn.freefarcy.com": null,
"casalemedia.com": null,
"harrenmedia.com": null,
"mediaplazza.com": null,
"ventivmedia.com": null,
"cqcounter.com": null,
"adserver.pressboard.ca": null,
"estat.com": null,
"ads.o2.pl": null,
"cdn.heapanalytics.com": null,
"adstest.weather.com": null,
"ads.resoom.de": null,
"picadmedia.com": null,
"reduxmedia.com": null,
"xtendmedia.com": null,
"optmnstr.com": null,
"crazypopups.com": null,
"popupnation.com": null,
"onestat.com": null,
"statsie.com": null,
"ads.krawall.de": null,
"adserver.twitpic.com": null,
"bigbangmedia.com": null,
"mediacharger.com": null,
"vibrantmedia.com": null,
"affiliation-france.com": null,
"paycounter.com": null,
"sexcounter.com": null,
"xxxcounter.com": null,
"adbunker.com": null,
"adcolony.com": null,
"adconion.com": null,
"ademails.com": null,
"adengage.com": null,
"adexpose.com": null,
"adflight.com": null,
"adimpact.com": null,
"adincube.com": null,
"adlegend.com": null,
"adminder.com": null,
"adonspot.com": null,
"adorigin.com": null,
"adperium.com": null,
"adremedy.com": null,
"adtechus.com": null,
"adthrive.com": null,
"adxvalue.com": null,
"adzbazar.com": null,
"inskinad.com": null,
"globalismedia.com": null,
"media6degrees.com": null,
"realcastmedia.com": null,
"pagerank4you.com": null,
"ewebcounter.com": null,
"ads.edbindex.dk": null,
"adverty.com": null,
"revstats.com": null,
"topstats.com": null,
"visistat.com": null,
"ad.nwt.cz": null,
"ads.gaming-universe.de": null,
"audience2media.com": null,
"mediaiqdigital.com": null,
"adminshop.com": null,
"adreactor.com": null,
"adreclaim.com": null,
"adrecover.com": null,
"adtriplex.com": null,
"advariant.com": null,
"adventory.com": null,
"consensad.com": null,
"predictad.com": null,
"Adsatt.go.starwave.com": null,
"rapidcounter.com": null,
"sugoicounter.com": null,
"bitmedianetwork.com": null,
"conversantmedia.com": null,
"steelhousemedia.com": null,
"ads.jubii.dk": null,
"ads.clearchannel.com": null,
"findyourcasino.com": null,
"goldstats.com": null,
"megastats.com": null,
"stats4all.com": null,
"centerpointmedia.com": null,
"hentaicounter.com": null,
"abruptroad.com": null,
"ad-rotator.com": null,
"adgardener.com": null,
"adrecreate.com": null,
"adrevolver.com": null,
"adxpansion.com": null,
"exchangead.com": null,
"ads.ft.com": null,
"tracking.inlocomedia.com": null,
"freewebcounter.com": null,
"adzestocp.com": null,
"harrenmedianetwork.com": null,
"neudesicmediagroup.com": null,
"indexstats.com": null,
"mousestats.com": null,
"rightstats.com": null,
"statxpress.com": null,
"admailtiser.com": null,
"adreporting.com": null,
"advertserve.com": null,
"adwitserver.com": null,
"complextoad.com": null,
"amazingcounters.com": null,
"optimallimit.com": null,
"creafi-online-media.com": null,
"adeimptrck.com": null,
"advertmarket.com": null,
"advertstream.com": null,
"advertwizard.com": null,
"onestatfree.com": null,
"brightmountainmedia.com": null,
"rlcdn.com": null,
"hurricanedigitalmedia.com": null,
"ads.massinfra.nl": null,
"ads.wiezoekje.nl": null,
"siteimproveanalytics.com": null,
"pgpartner.com": null,
"adjustnetwork.com": null,
"advertiserurl.com": null,
"enviousthread.com": null,
"ads.motor-forum.nl": null,
"advangelists.com": null,
"clicktrade.com": null,
"adexchangegate.com": null,
"advertisespace.com": null,
"advertisingbox.com": null,
"adworldnetwork.com": null,
"777partner.com": null,
"bttrack.com": null,
"enthusiasticdad.com": null,
"pro-advertising.com": null,
"adserver.break-even.it": null,
"cashpartner.com": null,
"advertiseireland.com": null,
"chickensstation.com": null,
"adcentriconline.com": null,
"icptrack.com": null,
"webads.co.nz": null,
"adnetinteractive.com": null,
"ads.dada.it": null,
"1-1ads.com": null,
"avsads.com": null,
"runads.com": null,
"tpnads.com": null,
"xapads.com": null,
"ads.deltha.hu": null,
"dmtracker.com": null,
"porntrack.com": null,
"adsmogo.com": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"ads2.xnet.cz": null,
"30ads.com": null,
"77tracking.com": null,
"tvmtracker.com": null,
"zantracker.com": null,
"game-advertising-online.com": null,
"ads.eu.msn.com": null,
"boomads.com": null,
"kindads.com": null,
"trackuhub.com": null,
"webtracky.com": null,
"ad.mgd.de": null,
"advertisementafterthought.com": null,
"forkcdn.com": null,
"prmtracking.com": null,
"trackalyzer.com": null,
"tracking101.com": null,
"appboycdn.com": null,
"tracking22.com": null,
"tracking42.com": null,
"ads.multimania.lycos.fr": null,
"aaxads.com": null,
"hueads.com": null,
"yepads.com": null,
"yesads.com": null,
"hypertracker.com": null,
"trackingsoft.com": null,
"trackmysales.com": null,
"identads.com": null,
"juicyads.com": null,
"popmyads.com": null,
"vivtracking.com": null,
"adserver.janes.com": null,
"ad.nttnavi.co.jp": null,
"gadsbee.com": null,
"specificmedia.co.uk": null,
"webtrackerplus.com": null,
"adtech.de": null,
"50websads.com": null,
"acuityads.com": null,
"deployads.com": null,
"disqusads.com": null,
"gothamads.com": null,
"medleyads.com": null,
"mellowads.com": null,
"rampidads.com": null,
"smart4ads.com": null,
"smartyads.com": null,
"ukbanners.com": null,
"leedsads.com": null,
"yieldads.com": null,
"affbuzzads.com": null,
"intelliads.com": null,
"monarchads.com": null,
"newstarads.com": null,
"rhombusads.com": null,
"samsungads.com": null,
"ilbanner.com": null,
"bannermall.com": null,
"bannerswap.com": null,
"basebanner.com": null,
"flexbanner.com": null,
"freebanner.com": null,
"trackingfestival.com": null,
"hueadsxml.com": null,
"mysafeads.com": null,
"posumeads.com": null,
"scoobyads.com": null,
"attributiontracker.com": null,
"smetrics.foxnews.com": null,
"infinityads.com": null,
"shoppingads.com": null,
"stickyadstv.com": null,
"popunder.ru": null,
"e-bannerx.com": null,
"bannerboxes.com": null,
"bannerimage.com": null,
"bannerpower.com": null,
"bannerspace.com": null,
"hueadsortb.com": null,
"247media.com": null,
"adview.com": null,
"bannerserver.com": null,
"bannersgomlm.com": null,
"free-banners.com": null,
"boffoadsapi.com": null,
"decenterads.com": null,
"flairadscpc.com": null,
"rtbflairads.com": null,
"wonderlandads.com": null,
"clickcompare.co.uk": null,
"valueclick.com": null,
"ads.ign.com": null,
"adx.atnext.com": null,
"bannertesting.com": null,
"compactbanner.com": null,
"iconadserver.com": null,
"newsadsppush.com": null,
"blogads.com": null,
"instinctiveads.com": null,
"popflawlessads.com": null,
"ad.admitad.com": null,
"ads.indiatimes.com": null,
"cosmopolitads.com": null,
"playmobileads.com": null,
"spaceleadster.com": null,
"adserver1.mindshare.de": null,
"british-banners.com": null,
"servadsdisrupt.com": null,
"ads.newsint.co.uk": null,
"ads.guardianunlimited.co.uk": null,
"ads.silverdisc.co.uk": null,
"ads.uknetguide.co.uk": null,
"vrtzcontextualads.com": null,
"adk2.com": null,
"js-agent.newrelic.com": null,
"buyingadsmadeeasy.com": null,
"ads2004.treiberupdate.de": null,
"shareasale.com": null,
"cognitiveadscience.com": null,
"adv.yo.cz": null,
"shinystat.com": null,
"intentmedia.net": null,
"ads.appsgeyser.com": null,
"web-stat.com": null,
"ads3.virtual-nights.com": null,
"webtrends.telegraph.co.uk": null,
"ads.wwe.biz": null,
"blogtopsites.com": null,
"ads.newsquest.co.uk": null,
"adserver.betandwin.de": null,
"pixel.condenastdigital.com": null,
"hidden.gogoceleb.com": null,
"ad2.lupa.cz": null,
"wintricksbanner.googlepages.com": null,
"adultadvertising.com": null,
"ads.brazzers.com": null,
"af-ad.co.uk": null,
"adhunter.media": null,
"ads.fairfax.com.au": null,
"sensismediasmart.com.au": null,
"eclick.vn": null,
"cjlog.com": null,
"logua.com": null,
"smetrics.bestbuy.com": null,
"banners.iq.pl": null,
"ads.townhall.com": null,
"ads.tripod.lycos.es": null,
"remotead.cnet.com": null,
"ymetrica1.com": null,
"imgpromo.easyrencontre.com": null,
"theadhost.com": null,
"logsss.com": null,
"ad-up.com": null,
"banner.vadian.net": null,
"adk2ads.tictacti.com": null,
"ads.rediff.com": null,
"extremetracking.com": null,
"rtbidhost.com": null,
"kissmetrics.com": null,
"ahalogy.com": null,
"ad01.mediacorpsingapore.com": null,
"alexametrics.com": null,
"adskeeper.co.uk": null,
"freelogs.com": null,
"directleads.com": null,
"bannery.cz": null,
"tracker.vgame.us": null,
"ads.tahono.com": null,
"ad.musicmatch.com": null,
"adbutler.com": null,
"trendcounter.com": null,
"webseoanalytics.com": null,
"ads4.clearchannel.com": null,
"googletagmanager.com": null,
"adimg.cnet.com": null,
"googletagservices.com": null,
"btez8.xyz": null,
"tracking.ibxlink.com": null,
"banner.orb.net": null,
"ads.fool.com": null,
"ads5.canoe.ca": null,
"ads.friendfinder.com": null,
"tracking.olx-st.com": null,
"tracking.gajmp.com": null,
"lemmatechnologies.com": null,
"adserver.freecity.de": null,
"carbonads.com": null,
"cluster.adultworld.com": null,
"adrotic.girlonthenet.com": null,
"ad.gate24.ch": null,
"adverticum.com": null,
"auctionads.com": null,
"ad.bondage.com": null,
"ads2.net-communities.co.uk": null,
"ad.wavu.hu": null,
"stats.merriam-webster.com": null,
"24log.de": null,
"ads.redlightcenter.com": null,
"sedotracker.com": null,
"dmtracking2.alibaba.com": null,
"adsco.re": null,
"bannerconnect.com": null,
"adbot.com": null,
"ads.verticalresponse.com": null,
"admix.in": null,
"adimages.omroepzeeland.nl": null,
"ad.ilove.ch": null,
"adext.inkclub.com": null,
"visit.webhosting.yahoo.com": null,
"stats.mirrorfootball.co.uk": null,
"stats.x14.eu": null,
"blogcounter.de": null,
"adserver.o2.pl": null,
"analytics.mytvzion.pro": null,
"adimages.sanomawsoy.fi": null,
"adbrn.com": null,
"stats.townnews.com": null,
"media-adrunner.mycomputer.com": null,
"banner.relcom.ru": null,
"imageads.canoe.ca": null,
"webstat.com": null,
"adsmart.com": null,
"adv.livedoor.com": null,
"admedia.com": null,
"mjxads.internet.com": null,
"ads2.clearchannel.com": null,
"downloadr.xyz": null,
"adsatt.abcnews.starwave.com": null,
"adsstat.com": null,
"admanager.btopenworld.com": null,
"bbn.img.com.ua": null,
"ads1.canoe.ca": null,
"htmlhubing.xyz": null,
"app-analytics.snapchat.com": null,
"ad.freecity.de": null,
"ads.hbv.de": null,
"customad.cnn.com": null,
"adserver.friendfinder.com": null,
"oas.benchmark.fr": null,
"admarvel.com": null,
"ads.watson.ch": null,
"ad4mat.com": null,
"admanager.carsoup.com": null,
"adv-banner.libero.it": null,
"ads.usatoday.com": null,
"freewheel.tv": null,
"ads10.speedbit.com": null,
"ads.prisacom.com": null,
"track.flexlinkspro.com": null,
"is-tracking-pixel-api-prod.appspot.com": null,
"stats.self.com": null,
"rle.ru": null,
"superstats.com": null,
"track.ultravpn.com": null,
"lead-analytics.nl": null,
"hexusads.fluent.ltd.uk": null,
"advertise.com": null,
"track.contently.com": null,
"track.flexlinks.com": null,
"ad.virtual-nights.com": null,
"eiv.baidu.com": null,
"ads2.jubii.dk": null,
"banner.elisa.net": null,
"wpnrtnmrewunrtok.xyz": null,
"ads.cbc.ca": null,
"track.nuxues.com": null,
"ads.blog.com": null,
"banner.cotedazurpalace.com": null,
"banners.thomsonlocal.com": null,
"adimgs.sapo.pt": null,
"banners.direction-x.com": null,
"wdads.sx.atl.publicus.com": null,
"analytics.samdd.me": null,
"tracker.icerocket.com": null,
"ilead.itrack.it": null,
"ads.nola.com": null,
"banner.webmersion.com": null,
"partner-ads.com": null,
"newt1.adultworld.com": null,
"stats2.self.com": null,
"track.viewdeos.com": null,
"metrics.api.drift.com": null,
"analytics.ext.go-tellm.com": null,
"hostedads.realitykings.com": null,
"rate.ru": null,
"add.newmedia.cz": null,
"ads2.brazzers.com": null,
"adsclicktech.com": null,
"metrics.windowsitpro.com": null,
"stats.hyperinzerce.cz": null,
"adcenter.net": null,
"ads-click.com": null,
"adserver.hwupgrade.it": null,
"banners.dine.com": null,
"ads.nj.com": null,
"ads.hollywood.com": null,
"adsys.townnews.com": null,
"adcycle.com": null,
"oas.uniontrib.com": null,
"securemetrics.apple.com": null,
"banner.coza.com": null,
"ad3.iinfo.cz": null,
"metrics.govexec.com": null,
"histats.com": null,
"ad.71i.de": null,
"ads.itv.com": null,
"admonitor.com": null,
"adclick.com": null,
"begun.ru": null,
"ntvk1.ru": null,
"pbnet.ru": null,
"webstat.channel4.com": null,
"ads.tripod.lycos.it": null,
"click.fool.com": null,
"analytics.siliconexpert.com": null,
"analytics.cohesionapps.com": null,
"click.absoluteagency.com": null,
"gostats.com": null,
"banners.cams.com": null,
"analytics.poolshool.com": null,
"sc-analytics.appspot.com": null,
"rmedia.boston.com": null,
"analytics.picsart.com": null,
"affiliatetracking.com": null,
"analytics.icons8.com": null,
"analytics.jabong.com": null,
"analytics.posttv.com": null,
"analytics.swiggy.com": null,
"belstat.com": null,
"ads.quoka.de": null,
"advertpro.ya.com": null,
"adcomplete.com": null,
"adformdsp.net": null,
"promotions-884485.c.cdn77.org": null,
"ad-server.gulasidorna.se": null,
"admob.com": null,
"code-server.biz": null,
"freestats.com": null,
"popup.msn.com": null,
"cooster.ru": null,
"hitlist.ru": null,
"ads-trk.vidible.tv": null,
"adv.hwupgrade.it": null,
"tangerinenet.biz": null,
"clickserve.cc-dt.com": null,
"track.mailerlite.com": null,
"adserver.71i.de": null,
"supertop.ru": null,
"audience.media": null,
"medyanetads.com": null,
"adcast.deviantart.com": null,
"adjuggler.yourdictionary.com": null,
"banners.passion.com": null,
"ad.hbv.de": null,
"afterview.ru": null,
"owebmoney.ru": null,
"cumbersomecloud.com": null,
"banner.linux.se": null,
"adserver.sanomawsoy.fi": null,
"assoc-amazon.com": null,
"ad.clix.pt": null,
"tracking01.walmart.com": null,
"adecn.com": null,
"adplus.co.id": null,
"advert.bayarea.com": null,
"intentmedia.com": null,
"ads.desmoinesregister.com": null,
"admeld.com": null,
"ads.digitalpoint.com": null,
"adres.internet.com": null,
"bizad.nikkeibp.co.jp": null,
"ads.channel4.com": null,
"newads.bangbros.com": null,
"ads.icq.com": null,
"ads.nyi.net": null,
"traffic.focuusing.com": null,
"adimg.uimserv.net": null,
"statm.the-adult-company.com": null,
"banner.penguin.cz": null,
"mads.cnet.com": null,
"webstats4u.com": null,
"ads.foxnetworks.com": null,
"smetrics.walgreens.com": null,
"coremetrics.com": null,
"banners.czi.cz": null,
"count.west263.com": null,
"adsatt.espn.go.com": null,
"adsrv.iol.co.za": null,
"admaster.com.cn": null,
"advideo.uimserv.net": null,
"banner.titan-dsl.de": null,
"mediasmart.io": null,
"ads.pni.com": null,
"banners.babylon-x.com": null,
"adserver.omroepzeeland.nl": null,
"clicktrack.ziyu.net": null,
"sponsors.thoughtsmedia.com": null,
"ads.berlinonline.de": null,
"affiliates.streamray.com": null,
"adforce.com": null,
"proxy-tracker.colpirio.com": null,
"ads.asiafriendfinder.com": null,
"metrics.ctv.ca": null,
"ads.detelefoongids.nl": null,
"analytics.htmedia.in": null,
"banner.tanto.de": null,
"adtech.com": null,
"counter.fateback.com": null,
"logger.snackly.co": null,
"mediamgr.ugo.com": null,
"bs.yandex.ru": null,
"advertpro.sitepoint.com": null,
"adman.otenet.gr": null,
"track1.viewdeos.com": null,
"amazon-adsystem.com": null,
"realmedia-a800.d4p.net": null,
"adserver.libero.it": null,
"topsites.com.br": null,
"banners.amigos.com": null,
"dmtracking.alibaba.com": null,
"counter.mojgorod.ru": null,
"tracker-pm2.spilleren.com": null,
"ad.hodomobile.com": null,
"ads.guardian.co.uk": null,
"cbanners.virtuagirlhd.com": null,
"mediaserver.bwinpartypartners.it": null,
"adadvisor.net": null,
"ads.businessweek.com": null,
"pix.spot.im": null,
"adclient.uimserv.net": null,
"eas.almamedia.fi": null,
"imonitor.nethost.cz": null,
"sharethrough.com": null,
"spotx.tv": null,
"stats.olark.com": null,
"bannersng.yell.com": null,
"count.rin.ru": null,
"xad.com": null,
"smetrics.washingtonpost.com": null,
"banner.cz": null,
"ads.iwon.com": null,
"metrics.gfycat.com": null,
"banner.buempliz-online.ch": null,
"counter.cz": null,
"mediageneral.com": null,
"clickbank.com": null,
"www-banner.chat.ru": null,
"adtechjp.com": null,
"adlightning.com": null,
"smetrics.ctv.ca": null,
"propellerads.com": null,
"comclick.com": null,
"babs.tv2.dk": null,
"alphonso.tv": null,
"admarketplace.net": null,
"hgads.com": null,
"oas.roanoke.com": null,
"oas.toronto.com": null,
"ads-twitter.com": null,
"mediax.angloinfo.com": null,
"nativeroll.tv": null,
"affec.tv": null,
"getclicky.com": null,
"logs.roku.com": null,
"connect.facebook.com": null,
"connect.facebook.net": null,
"platform.twitter.com": null,
"api.areametrics.com": null,
"api.beaconsinspace.com": null,
"mobileapi.mobiquitynetworks.com": null,
"incoming-data-sense360.s3.amazonaws.com": null,
"ios-quinoa-events-prod.sense360eng.com": null,
"ios-quinoa-high-frequency-events-prod.sense360eng.com": null,
"v1.blueberry.cloud.databerries.com": null,
"outbrain.com": null,
"taboola.com": null };
var bad_da_host_exact_flag = 1492 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^$/;
var bad_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 6 rules:
var bad_da_hostpath_JSON = { "stroi-help.ru/forum/script_new.js": null,
"cmath.fr/images/fond2.gif": null,
"helpsetup.ru/home/solnisko.php": null,
"cmath.fr/images/fondsticky.gif": null,
"jappy.tv/i/wrbng/abb.png": null,
"bdgest.com/js/site.js": null };
var bad_da_hostpath_exact_flag = 6 > 0 ? true : false;  // test for non-zero number of rules
    
// 10 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:static\.game\-state\.com\/images\/main\/alert\/replacement\/|ed\-protect\.org\/cdn\-cgi\/apps\/head\/|vsthouse\.ru\/a\-detector\/|ipprof\.ru\/wp\-content\/plugins\/ad\-blocking\-advisor\/|sdamgia\.ru\/img\/blockadblock_|sea\-man\.org\/adb_script\/|google\.com\/pagead|facebook\.com\/plugins\/|vazhno\.ru\/cdn\-cgi\/apps\/head\/(?=([\s\S]*?\.js))\1|nikopik\.com\/wp\-content\/themes\/(?=([\s\S]*?\/js\/nikopik\.js))\2)/i;
var bad_da_hostpath_regex_flag = 10 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^$/;
var bad_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 499 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:analytics\.popsci\.com|ads\.xtra\.ca|ad\.mail\.ru|ads\.sina\.com|msg2\.video\.ptqy\.gitv\.tv|ads\.com\.ru|cdn\.taboola\.com|adservice\.google\.com|stat\.m\.tv\.sohu\.com|metrica\.yandex\.ru|adservice\.google\.de|ads\.chinatimes\.com|msg\.video\.ptqy\.gitv\.tv|minisite\.vidown\.cn|ads\.bridgetrack\.com|media\.lbn\.ru|slog\.sina\.cn|adserver\.news\.com|ads\.supplyframe\.cn|cdn\.adswizz\.com|adsdk\.yandex\.ru|ads\.yimg\.com|cdn\.sail\-horizon\.com|affiliate\.rakuten\.com|cdn\.skimresources\.com|status\.hotjar\.com|adm\.hotjar\.com|ads\.fortunecity\.org|game\.pps\.tv|ads\.imguol\.com|ads\.fortunecity\.de|ad\.api\.3g\.youku\.com|mobile\.activeshopper\.com|status\.segment\.com|freewebs\.getclicky\.com|advertising\.yandex\.ru|adlog\.com|event\-api\.contactatonce\.co\.uk|assets\.hotjar\.com|log\.rutube\.ru|popups\.ru|cdn\.demdex\.net|mobtop\.ru|ad\.ddestiny\.ru|affiliates\.bfast\.com|adobe\.demdex\.net|affiliate\.2mdn\.net|static\.2mdn\.net|adm\.baidu\.com|ads\.nordichardware\.com|dashboard\.addthis\.com|ads\.atom\.com|metrics\.brightcove\.com|clicks\.dealer\.com|image\.adition\.com|static\.hotjar\.com|mobile\-crash\-origin\.newrelic\.com|mobile\-collector\.newrelic\.com|mobile\-crash\.newrelic\.com|events\.segment\.com|ads\.nwsource\.com|ad\.rambler\.ru|mobile\-service\.segment\.com|stat\.social|dashboard\.adcalls\.nl|adinfo\.ru|<link rel='stylesheet' href='\/css\/pgl\.css' type='text\/css'><\/head>|ads\.mopub\.pub|ad2\.rambler\.ru|ads\.contentabc\.net|ads\.supfast\.net|cdn\.nsimg\.net|optimize\.webtrends\.com|cbsdigitalmedia\.hb\.omtrdc\.net|ads\.tripod\.com|postmedia\.demdex\.net|ads\.evidon\.com|static\.segment\.com|mediator\.mail\.ru|surveys\.hotjar\.com|metrics\.aviasales\.ru|cdn\.viglink\.com|metrica\.yandex\.com|data\.videonow\.ru|assets\.servedby\-buysellads\.com|dominocounter\.free\.fr|counter\.rambler\.ru|richmedia\.yimg\.com|brand\.ad|ads\.msn\.com|log\.loveota\.net|mobile\-global\.baidu\.com|mobojs\.baidu\.com|img\.mediaplex\.com|ad2\.yam\.com|ads\.thestar\.com|stats\.mos\.ru|metrics\.expressen\.se|ads\.eastbayexpress\.com|img\.litix\.io|mobitema\.ru|mobileader\.ru|mobioffers\.ru|moby\-aa\.ru|ads\.linkedin\.com|mobiile\-service\.ru|applog\.camera360\.com|stat24\.ru|metrica\.yandex\.kz|ad\.games\.ch|ads\.contentabc\.com|metrics\.dollargeneral\.com|click\.supfast\.net|adfox\.yandex\.ru|pixel\.wp\.tv|track\.price\.ru|ads\.hulu\.com|image\.versiontracker\.com|adservice\.google\.ie|affiliates\.match\.com|cdn\.videoplaza\.tv|segment\-data\-us\-east\.zqtk\.net|data\.neosmi\.ru|segment\-data\.zqtk\.net|mobile\.game\-insight\.com|counter\.pixplug\.in|cdn\.pardot\.com|metrica\.yandex\.by|partners\.popmatters\.com|cdn\.videonow\.ru|mobads\.baidu\.com|scripts\.ivstracker\.net|advertise\.ru|kaspersky\.d3\.sc\.omtrdc\.net|stat\.media|share\.yandex\.ru|metrica\.yandex\.ua|dualstack\.adsame\-1421766300\.ap\-southeast\-1\.elb\.amazonaws\.com|tracking\.taboola\.com|aimg\.media\.net|pixel\.ad|advideo\.ru|admob\.biz|static\-72\-26\-207\-6\.assets\.qhosted\.com|charter\.demdex\.net|ad\.lolipop\.jp|powered\-by\.securewebsiteaccess\.com|adservice\.google\.nl|sclick\.baidu\.com|partners\.segment\.com|\/adb_script\/|branding\.taboola\.com|ads\.lycos\.fr|clck\.yandex\.ru|freestats\.biz|ads\.medscape\.com|eclick\.baidu\.com|recreativ\.ru|adcomplete\.ru|scripts\.webcontentassessor\.com|admob\.ru|status\.optimizely\.com|popads\.media|analytics\.mobile\.yandex\.net|gostats\.ru|ads\.sina\.com\.hk|admax\.go2cloud\.org|bidtraffic\.ru|adsmart\.ru|cdn\.evidon\.com|cdn\.speedshiftmedia\.com|printthis\.clickability\.com|\/adblock\-img\.|events\.adjust\.com|topstat\.ru|pixel\.watch|static\.media\.magnify\.net\.s3\.amazonaws\.com|img\.mmcdn\.cn|impcz\.adocean\.pl|analytics\.freedom\.com|adone\.ru|down\.ruanmei\.com|host4\.list\.ru|load\.s3\.amazonaws\.com|ads\.zdnet\.de|scripts\.affiliatefuture\.com|advmaker\.ru|openstat\.ru|adclick\.ru|ad\-creatives\-public\.commondatastorage\.googleapis\.com|metrika\.yandex\.ru|ipinyou\.com|counter\.cam\-content\.com|banners\.sextracker\.com|adimg\.tv\.com|upload\.salmonads\.com|adforce\.ru|ad\.terra\.doubleclick\.net|tracking\.shopping\-flux\.com|cdn\.matheranalytics\.com|ads\.link4ads\.com|ads\.whaleads\.com|adservice\.google\.ca|visit\-tracker\.biz|adflow\.ru|track\.express\.de|merchants\.viglink\.com|admulti\.ru|advertbox\.ru|adbureau\.ru|adkeeper\.ru|adregain\.ru|advergine\.ru|creatives\.doubleclick\.net|static\.ads\-twitter\.com|skyad\.video|surveys\-staging\.hotjar\.com|cdn\.leon\.ru|adjs\.ru|adimage\.media|medianaft\.ru|creara\-media\.ru|pc2ads\.ru|adstock\.ru|cdn\.ambientplatform\.vn|mediaview\.nielsen\.com|rtlog\.vidown\.cn|clicknj\.taboola\.com|chartaca\.com\.s3\.amazonaws\.com|merchant\.linksynergy\.com|stat\.aport\.ru|openad\.ru|cdn\.adblade\.com|trafficjunky\.xtube\.com|adbit\.biz|rtb\-media\.ru|ad\.pixnet\.net|adnet\.biz|affiliation\.rueducommerce\.fr|stats\.greenpixels\.com|stats\.fileplanet\.com|status\.logrocket\.com|platform\.sharethis\.com|login\.dotomi\.com|adwolf\.ru|ad\.linksynergy\.com|events\.vungtv\.net|adsplay\.xyz|ucoz\.ru|vidstat\.taboola\.com|vidstatb\.taboola\.com|adcenter\.scripps\.com|advertpay\.ru|apicdn\.viglink\.com|advertstar\.ru|media\.ambientplatform\.vn|rmcdn\.2mdn\.net|download\.123cw\.cn|ad\.cpe\.dotomi\.com|perscdn\.taboola\.com|adnet\.ru|ads\.game\.net|images\.skimresources\.com|ads\.dotomi\.com|rlog\.video\.qq\.com|mads\.advertising\.com|adv\.medscape\.com|kineclick\.free\.fr|ads\.shopstyle\.com|ads2\.eqads\.com|partners\.parimatch\.net|sdklog\.cmgame\.com|adserver\.tappsgames\.com|b0\.a2\.top\.mail\.ru|content\.ad|mads\.download\.com|ads\.lycos\.de|optimize\.viglink\.com|pixel\.4pcdn\.de|arouersobesite\.free\.fr|cityads\.ru|staging\-custom\-event\-inserter\.newrelic\.com|fast\.anz\.demdex\.net|fast\.rbi\.demdex\.net|analytics\.msnbc\.com|fast\.nrjgroup\.demdex\.net|nclick\.ru|static\.quantcast\.mgr\.consensu\.org|img\.adpush\.cn|click\.gamersky\.com|citi\.bridgetrack\.com|track\.games\.la|ads\.traderonline\.com|analytics\.nativeads\.com|metrics\.cvshealth\.com|track\.eyeviewads\.com|adops\.sharethis\.com|mobile\.smartadserver\.com|vidanalytics\.taboola\.com|widget\.sharethis\.com|adpremium\.ru|mads\.tv\.com|click\.ru|metric\.bizjournals\.com|ads\.apn\.co\.za|adland\.ru|survey\.g\.doubleclick\.net|warlog\.ru|cdn\.tt\.omtrdc\.net|image\.adthor\.com|ads\.crakmedia\.com|cnstats\.ru|download\.bav\.baidu\.com|bannerbank\.ru|tracker\.baidu\.com|cdn\.mediavoice\.com|server1\.adexit\.com|cmstrendslog\.timesnow\.tv|creative\.nscash\.com|idvisitor\.click2houston\.com|guce\.adtech\.de|form\-cdn\.pardot\.com|blog\.adblade\.com|account\.evidon\.com|metrics\.att\.com|itest\.propellerads\.com|imgstat\.baidu\.com|gomtdatacom\.xyz|images\.bimedia\.net|tgptraffic\.biz|click2\.cafepress\.com|beertraffic\.biz|trafficcash\.biz|static\.adhood\.com|img\.sharethis\.com|fandango\.tt\.omtrdc\.net|inetlog\.ru|trafficfactory\.biz|dishad\.trade|addan\.xyz|web\-ad\.xyz|banners\.bol\.se|admonitor\.thepaper\.cn|olymiohad\.xyz|ad\.adapter\.kaffnet\.com|banners\.advidi\.com|pixel\.advertising\.com|campaign\.adobe\.com|trackermap\.evidon\.com|mobile\-symbol\-upload\.newrelic\.com|syndication\-o\.twimg\.com|segment\.a3cloud\.net|ifyoucouldjobs\.imgix\.net|makecashtakingsurveys\.biz|recommendedforyou\.xyz|guce\.adtechjp\.com|extension\-cdn\.evidon\.com|tagcontrol\-cdn\.evidon\.com|cdn\-settings\.segment\.com|ads\.bittorrent\.com|pzz\.events|analytics\.ooyala\.com|data\.ero\-advertising\.com|smartadserver\.ru|ads\.bta\.bg|banner\.linksynergy\.com|ad\.ru|track\.bizjournals\.com|webtrekk\.mediaset\.net|bannerhost\.ru|mi\.ads\.mp\.mydas\.mobi|ads\.tripod\.jubii\.dk|adproxy\.whowhere\.com|premiumstats\.xyz|awaps\.yandex\.ru|gigaads\.xyz|adthebest\.online|stats\.livingsocial\.com|n1275adserv\.xyz|n1278adserv\.xyz|n1307adserv\.xyz|n1809adserv\.xyz|dryjaunerrads\.xyz|gcdn\.2mdn\.net|alreadsbacking\.xyz|images\.specificclick\.net|trafficcost\.ru|traffic\.ru|ads\.com\.tr|static\.freenet\.de|pagead2\.googleadservices\.com|assets\.logrocket\.com|track\.linksynergy\.com|data\.video\.qiyi\.com|ads\.playboy\.bg|tracking\.livingsocial\.com|static\.servedby\-buysellads\.com|pbs\.bb\.ru|al21\.luxup\.ru|24log\.ru|data2\.ero\-advertising\.com|spylog\.ru|creatives1\.ftimg\.net|toolbar\.baidu\.com|mads\.com|popup\.taboola\.com|ads\.bing\.com|popunder\.paypopup\.com|img1\.iphone\.mxweas\.com|paripartners\.online|an1435adserv\.online|campaign\-tracker\.us\-west\-2\.prod\.expedia\.com|mobus\.cn|engine\.pgmediaserve\.com|files\.adform\.net|videoclick\.ru|video\.adaptv\.advertising\.com|textad\.socialsex\.com|images\.shareaholic\.com|adsyst\.biz|media\.addynamix\.com|adserver\.snapads\.com|analytics\.adkernel\.com|login\-origin\.newrelic\.com|clickgate\.biz|ads\.socialbakers\.com|brandomatic\.ru|ad\.xmovies8\.ru|ad\.adnow\.com|promclickapp\.biz|bidagent\.xad\.com|adimg\.download\.com|cpaevent\.ru|ads\.independent\.ie|webtrack\.biz|partners\.a24\.biz|rcounter\.rambler\.ru|scounter\.rambler\.ru|teads\.tv|mediator\.imgsmail\.ru|tags\.msnbc\.com|ad999\.biz|adcast\.ru|gungunlog\.xyz|backlogtop\.xyz|ad\-tag\.biz|advbox\.biz|hearinglogd\.xyz|sveincelogd\.xyz|beighnamsdlog\.xyz|healmetahtlog\.xyz|adultcomix\.biz|adpenguin\.biz|lead\.im|ad2adnetwork\.biz|adv\.aport\.ru|itsdata\.map\.baidu\.com|php4you\.biz|ad1\.ru|store\.ptqy\.gitv\.tv|istat\.biz|metrics\.tvguide\.com|yads\.c\.yimg\.jp|254a\.comjs\.moatads\.com|log\.vcgame\.cn|ingameads\.gameloft\.com|ingamesads\.gameloft\.com|adimg1\.chosun\.org|nsclickvideo\.baidu\.com|cloud\.datasphere\.com|qianclick\.baidu\.com|fexclick\.baidu\.com|caclick\.baidu\.com|duclick\.baidu\.com|nsclick\.baidu\.com|datamarket\.baidu\.com|fclick\.baidu\.com|datax\.baidu\.com|ad\.ad\-stir\.com|4click\.ru|codata\.ru|2xclick\.ru|seclick\.ru|upclick\.ru|mt\-data\.ru|pornads\.biz|pushads\.biz|clickbux\.ru|clickvip\.ru|redclick\.ru|wmclickz\.ru|lead\-analytics\.biz|datamind\.ru|mtdata10\.ru|clickhere\.ru|pay\-click\.ru|zoomclick\.ru|staging\-beacon\-1\.newrelic\.com|islamclick\.ru)/i;
var bad_url_parts_flag = 499 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_RegExp = /^$/;
var good_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_url_RegExp = /^$/;
var bad_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0",
"172.16.0.0,        255.240.0.0",
"192.168.0.0,       255.255.0.0",
"127.0.0.0,         255.0.0.0",
"17.0.0.0,          255.0.0.0",
"23.2.8.68,         255.255.255.255",
"23.2.145.78,       255.255.255.255",
"23.39.179.17,      255.255.255.255",
"23.63.98.0,        255.255.254.0",
"104.70.71.223,     255.255.255.255",
"104.73.77.224,     255.255.255.255",
"104.96.184.235,    255.255.255.255",
"104.96.188.194,    255.255.255.255",
"65.52.0.0,         255.255.252.0" ];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [ "17.172.28.11,     255.255.255.255",
"134.170.30.202,    255.255.255.255",
"137.116.81.24,     255.255.255.255",
"157.56.106.189,    255.255.255.255",
"184.86.53.99,      255.255.255.255",
"2.22.61.43,        255.255.255.255",
"2.22.61.66,        255.255.255.255",
"204.79.197.200,    255.255.255.255",
"23.218.212.69,     255.255.255.255",
"65.39.117.230,     255.255.255.255",
"65.52.108.33,      255.255.255.255",
"65.55.108.23,      255.255.255.255",
"64.4.54.254,       255.255.255.255" ];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [ "61.139.105.128,    255.255.255.192",
"63.140.35.160,  255.255.255.248",
"63.140.35.168,  255.255.255.252",
"63.140.35.172,  255.255.255.254",
"63.140.35.174,  255.255.255.255",
"66.150.161.32,  255.255.255.224",
"66.235.138.0,   255.255.254.0",
"66.235.141.0,   255.255.255.0",
"66.235.143.48,  255.255.255.254",
"66.235.143.64,  255.255.255.254",
"66.235.153.16,  255.255.255.240",
"66.235.153.32,  255.255.255.248",
"81.31.38.0,     255.255.255.128",
"82.98.86.0,     255.255.255.0",
"89.185.224.0,   255.255.224.0",
"207.66.128.0,   255.255.128.0" ];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]*)(\\??\\S*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24})\\.?", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;

    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-export
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

// EasyList filtering for FindProxyForURL(url, host)
function EasyListFindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;

    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;

    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////

    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////

        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return proxy;
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [Firefox, about:config]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////

    if (scheme == "https" || scheme == "http") {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return proxy;
}

// User-supplied FindProxyForURL()
function FindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".local") || dnsDomainIs(host, ".LOCAL")
   /*
       Fix iOS 13 PAC file issue with Mail.app
       See: https://forums.developer.apple.com/thread/121928
   */
   ||
   // Apple
   (host == "imap.mail.me.com") || (host == "smtp.mail.me.com") ||
   dnsDomainIs(host, "imap.mail.me.com") || dnsDomainIs(host, "smtp.mail.me.com") ||
   (host == "p03-imap.mail.me.com") || (host == "p03-smtp.mail.me.com") ||
   dnsDomainIs(host, "p03-imap.mail.me.com") || dnsDomainIs(host, "p03-smtp.mail.me.com") ||
   (host == "p66-imap.mail.me.com") || (host == "p66-smtp.mail.me.com") ||
   dnsDomainIs(host, "p66-imap.mail.me.com") || dnsDomainIs(host, "p66-smtp.mail.me.com") ||
   // Google
   (host == "imap.gmail.com") || (host == "smtp.gmail.com") ||
   dnsDomainIs(host, "imap.gmail.com") || dnsDomainIs(host, "smtp.gmail.com") ||
   // Yahoo
   (host == "imap.mail.yahoo.com") || (host == "smtp.mail.yahoo.com") ||
   dnsDomainIs(host, "imap.mail.yahoo.com") || dnsDomainIs(host, "smtp.mail.yahoo.com") ||
   // Comcast
   (host == "imap.comcast.net") || (host == "smtp.comcast.net") ||
   dnsDomainIs(host, "imap.comcast.net") || dnsDomainIs(host, "smtp.comcast.net")
   /*
       Proxy bypass hostnames
   */
   ||
   // Apple Mobile Software Update
   (host == "mesu.apple.com") || dnsDomainIs(host, "mesu.apple.com")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}   
