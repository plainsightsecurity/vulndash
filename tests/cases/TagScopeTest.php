<?php
declare(strict_types=1);

// Tenant isolation - the most important property of the app. A client only
// ever sees assets carrying one of their tags; untagged assets and other
// tenants' assets are invisible; an account with no tags sees nothing.

use VulnDash\Lib\VulnerabilityRepository as V;

test('admin sees every asset and finding', function () {
    seed_estate();
    eq(V::getAssetCount([], true), 3, 'assets');
    eq(V::getDetectionsCount([], true, []), 4, 'findings');
});

test('client sees only their own tag', function () {
    seed_estate();
    eq(V::getAssetCount([1], false), 1, 'assets');
    eq(V::getDetectionsCount([1], false, [], null, false, 2), 2, 'findings');
    $hosts = array_unique(array_column(V::getDetectionsForExport([1], false, [], null, null, 2), 'hostname'));
    eq(array_values($hosts), ['host-a'], 'export hostnames');
});

test('client cannot widen scope by picking another tenant\'s tag', function () {
    seed_estate();
    // An out-of-scope view tag is ignored (falls back to the client's own
    // tags) - it must never reach the other tenant's assets.
    $hosts = array_unique(array_column(V::getDetectionsForExport([1], false, [], 2, null, 2), 'hostname'));
    eq(array_values($hosts), ['host-a'], 'export with viewTag 2');
    eq(V::getDetectionsCount([1], false, [], 2, false, 2), 2, 'count with viewTag 2');
    eq(V::getAssetCount([1], false, 2), 1, 'assets with viewTag 2');
});

test('client with no tags sees nothing (fails closed)', function () {
    seed_estate();
    eq(V::getAssetCount([], false), 0, 'assets');
    eq(V::getDetectionsCount([], false, [], null, false, 2), 0, 'findings');
    eq(array_sum(V::getSeverityCounts([], false, null, false, 2)), 0, 'severity counts');
});

test('severity counts respect scope', function () {
    seed_estate();
    $c = V::getSeverityCounts([1], false, null, false, 2);
    eq([$c[5], $c[4], $c[3], $c[2]], [1, 0, 1, 0]);
});
