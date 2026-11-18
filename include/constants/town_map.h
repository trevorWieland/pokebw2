#ifndef POKEBW2_CONSTANTS_TOWN_MAP_H
#define POKEBW2_CONSTANTS_TOWN_MAP_H

// The pseudo flags the town map asks about besides event flags (TownMap_CheckFlag), which the
// res/town_map/<zone>.json files name
#define TOWNMAP_FLAG_ONE_SHOT_DR 0xf000
#define TOWNMAP_FLAG_UNITY_TOWER_VISITED 0xf001
// Set while the Plasma Frigate is at its own place on the map (EVENT_WORK_PLASMA_FRIGATE_LOCATION is 3)
#define TOWNMAP_FLAG_PLASMA_FRIGATE 0xf002

// Where the Plasma Frigate is (EVENT_WORK_PLASMA_FRIGATE_LOCATION), which TownMap_GetMapZone turns into the place the
// map shows. The scripts set each value when the frigate moves there
enum {
    PLASMA_FRIGATE_LOCATION_PWT,
    PLASMA_FRIGATE_LOCATION_ROUTE_21,
    PLASMA_FRIGATE_LOCATION_GIANT_CHASM,
    PLASMA_FRIGATE_LOCATION_ITSELF,
};

#endif // POKEBW2_CONSTANTS_TOWN_MAP_H
