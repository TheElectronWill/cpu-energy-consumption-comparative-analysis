# Implémentation des sondes RAPL

## MSR

RAPL est exposé par le biais de Model Specific Registers, ou MSR.
Ces registres sont documentés dans le _Intel Software Developer Manual, volume 3B_, chapitre _Power and Thermal Management_, section _15.10.1 - RAPL interfaces_.

Le registre 64 bits `MSR_RAPL_POWER_UNIT` donne les unités des compteurs RAPL.
Celui qui nous intéresse est _Energy Status Unit_ ou `ESU`, stockés dans les bits 12 à 8.

On peut ensuite lire les bits 31 à 0 des registres :
- `MSR_PKG_ENERGY_STATUS`
- `MSR_PP0_ENERGY_STATUS`
- `MSR_PP1_ENERGY_STATUS`
- `MSR_DRAM_ENERGY_STATUS`
- `MSR_PLATFORM_ENERGY_STATUS`

### Calcul du compteur et overflow

Chaque registre est un compteur cumulatif d'énergie consommée. L'unité de ce compteur est `(1/2)^ESU` Joules.

$\text{msr\_to\_joules}(m) = m \times 0.5^{ESU}$

Le cpu y ajoute sa consommation toutes les 0.976 millisecondes environ. Il va donc déborder (overflow) au bout d'un certain temps (qui dépend de la consommation du domaine). Ça peut aller vite ! Le manuel évoque un temps d'environ 60 secondes lors d'une "consommation élevée".

Contrairement à d'autres registres, le cpu ne signale pas les overflow pour les compteurs d'énergie RAPL. Il faut donc mesurer à une fréquence suffisamment élevée pour ne pas en rater.

Correction d'overflow :
$$
\Delta m =
\begin{cases}
  \text{u32::max} - m_{prev} + m_{current} &\text{si}\ m_{current} < m_{prev} \\
  m_{current} - m_{prev} &\text{sinon} \\
\end{cases}
$$

### Attention à la mesure

Puisqu'il est cumulatif, il faut prendre deux mesures avec un petit intervalle de temps entre les deux, et calculer leur différence. Sans point de départ connu la valeur n'a aucun sens (énergie consommée mais depuis quand ?). Ceci est valable pour toutes les interfaces d'accès aux compteurs d'énergie RAPL.

## Perf event

TODO explications générales

### Calcul du compteur et overflow

L'interface perf [semble calculer la différence](https://github.com/torvalds/linux/blob/921bdc72a0d68977092d6a64855a1b8967acc1d9/arch/x86/events/rapl.c#LL200C2-L200C2) entre le compteur courant et sa valeur précédente, avant de l'ajouter au compteur de l'évènement exposé. Nos tests confirment que la valeur exposée par l'interface est un [entier 64 bits](https://lwn.net/Articles/573602/).

Correction d'overflow :
$$
\Delta m =
\begin{cases}
  \text{u64::max} - m_{prev} + m_{current} &\text{si}\ m_{current} < m_{prev} \\
  m_{current} - m_{prev} &\text{sinon} \\
\end{cases}
$$

## Powercap

La hiérarchie des "power zones" se situe dans `/sys/devices/virtual/powercap/intel-rapl`.
Chaque zone correspond à un domaine ou sous-domaine RAPL.

Exemple sur un laptop récent :
```
intel-rapl
  |
  |--- intel-rapl:0
  |     |--- intel-rapl:0:0
  |     |--- intel-rapl:0:1
  |     |--- intel-rapl:0:2
  |
  |--- intel-rapl:1
```

Pour chaque zone, on a :
- `name` : nom de la zone parmi les formats listés ci-dessous. Donne le domaine RAPL associé.
    - `package-N` où N est le numéro du package (socket)
    - `psys` : domaine "Platform"
    - `core` : domaine "Power Plane 0"
    - `uncore` : domaine "Power Plane 1"
    - `dram`
- `energy_uj` : valeur courante du compteur d'énergie, en **microJoules**
- `max_energy_uj` : valeur maximale du compteur avant overflow, en microJoules, ci-après notée $max_e$ .

### Calcul du compteur et overflow

Le compteur de powercap est calculé à la demande à partir du compteur MSR,  qui est converti en Joules avec la "bonne" unité ([sélectionnée en fonction du domaine et du type de matériel](https://github.com/torvalds/linux/blob/9e87b63ed37e202c77aa17d4112da6ae0c7c097c/drivers/powercap/intel_rapl_common.c#L167)).

$e_{uj} = \text{msr\_to\_joules}(m) \times 1000$

Chaque overflow du compteur MSR $m$ entraîne un overflow de $e_{uj}$.

Correction d'overflow :
$$
\Delta e_{uj} =
\begin{cases}
  max_{e} - e_{prev} + e_{current} &\text{si}\ e_{current} < e_{prev} \\
  e_{current} - e_{prev} &\text{sinon} \\
\end{cases}
$$
